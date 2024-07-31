package main
// TODO Add LICENSE file back (was MIT before modification)

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/parnurzeal/gorequest"
	"github.com/rakyll/magicmime"
)

const (
	name     = "fileinfo"
	category = "metadata"
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string

	fi FileInfo

	mtx sync.Mutex
)

type pluginResults struct {
	ID       string   `structs:"id"`
	FileInfo FileInfo `structs:"fileinfo"`
}

// FileMagic is file magic
type FileMagic struct {
	Mime        string `json:"mime" structs:"mime"`
	Description string `json:"description" structs:"description"`
}

// FileInfo json object
type FileInfo struct {
	Magic    FileMagic         `json:"magic" structs:"magic"`
	SSDeep   string            `json:"ssdeep" structs:"ssdeep"`
	TRiD     []string          `json:"trid" structs:"trid"`
	Exiftool map[string]string `json:"exiftool" structs:"exiftool"`
	MarkDown string            `json:"markdown,omitempty" structs:"markdown,omitempty"`
}

// GetFileMimeType returns the mime-type of a file path
func GetFileMimeType(ctx context.Context, path string) error {

	utils.Assert(magicmime.Open(magicmime.MAGIC_MIME_TYPE | magicmime.MAGIC_SYMLINK | magicmime.MAGIC_ERROR))
	defer magicmime.Close()

	mimetype, err := magicmime.TypeByFile(path)
	if err != nil {
		fi.Magic.Mime = err.Error()
		return err
	}

	fi.Magic.Mime = mimetype
	return nil
}

// GetFileDescription returns the textual libmagic type of a file path
func GetFileDescription(ctx context.Context, path string) error {

	utils.Assert(magicmime.Open(magicmime.MAGIC_SYMLINK | magicmime.MAGIC_ERROR))
	defer magicmime.Close()

	magicdesc, err := magicmime.TypeByFile(path)
	if err != nil {
		fi.Magic.Description = err.Error()
		return err
	}

	fi.Magic.Description = magicdesc
	return nil
}

// ParseExiftoolOutput convert exiftool output into JSON
func ParseExiftoolOutput(exifout string, err error) map[string]string {

	if err != nil {
		m := make(map[string]string)
		m["error"] = err.Error()
		return m
	}

	var ignoreTags = []string{
		"Directory",
		"File Name",
		"File Permissions",
		"File Modification Date/Time",
	}

	lines := strings.Split(exifout, "\n")

	log.Debugln("Exiftool lines: ", lines)

	if utils.SliceContainsString("File not found", lines) {
		return nil
	}

	datas := make(map[string]string, len(lines))

	for _, line := range lines {
		keyvalue := strings.Split(line, ":")
		if len(keyvalue) != 2 {
			continue
		}
		if !utils.StringInSlice(strings.TrimSpace(keyvalue[0]), ignoreTags) {
			datas[strings.TrimSpace(utils.CamelCase(keyvalue[0]))] = strings.TrimSpace(keyvalue[1])
		}
	}

	return datas
}

// ParseSsdeepOutput convert ssdeep output into JSON
func ParseSsdeepOutput(ssdout string, err error) string {

	if err != nil {
		return err.Error()
	}

	// Break output into lines
	lines := strings.Split(ssdout, "\n")

	log.Debugln("ssdeep lines: ", lines)

	if utils.SliceContainsString("No such file or directory", lines) {
		return ""
	}

	// Break second line into hash and path
	hashAndPath := strings.Split(lines[1], ",")

	return strings.TrimSpace(hashAndPath[0])
}

// ParseTRiDOutput convert trid output into JSON
func ParseTRiDOutput(tridout string, err error) []string {

	if err != nil {
		return []string{err.Error()}
	}

	keepLines := []string{}

	lines := strings.Split(tridout, "\n")

	log.Debugln("TRiD lines: ", lines)

	if utils.SliceContainsString("Error: found no file(s) to analyze!", lines) {
		return nil
	}

	lines = lines[6:]

	for _, line := range lines {
		if len(strings.TrimSpace(line)) != 0 {
			keepLines = append(keepLines, strings.TrimSpace(line))
		}
	}

	return keepLines
}
