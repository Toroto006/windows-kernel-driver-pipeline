package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"io/ioutil"
	"time"
    "net/http"
    "crypto/tls"

	"gopkg.in/resty.v1"
	"github.com/malice-plugins/pkgs/utils"
)

const (
	coordinatorURL = "http://coordinator:5000"
)

type FilesResponse struct {
	Files []File `json:"files"`
} 

// File represents information about a file
type File struct {
	ID       int    `json:"id"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	SHA1     string `json:"sha1"`
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
	SSDeep   string `json:"ssdeep"`
}

func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	for {
		files := getNonIdentifiedFiles()
		for _, file := range files {
			fileInfo := identifyFile(file)

			// Send the file info to the coordinator as a json
			fileInfoJSON, err := json.Marshal(fileInfo)
			if err != nil {
				log.Fatalf("failed to marshal file info: %v", err)
			}
			// fmt.Println(string(fileInfoJSON))
			resp, err := resty.R().
				SetHeader("Content-Type", "application/json").
				SetBody(fileInfoJSON).
				Post(coordinatorURL + "/files/" + fmt.Sprintf("%d", file.ID))
			if err != nil {
				log.Fatalf("failed to send file info: %v", err)
			}
			if resp.StatusCode() != 200 {
				log.Fatalf("failed to send file info: %d and error %s", resp.StatusCode(), resp.Body())
			}
		}
		time.Sleep(10 * time.Second)
	}
}

func getNonIdentifiedFiles() []File {
	var files FilesResponse
	resp, err := resty.R().Get(coordinatorURL + "/unidentified-files-info")
	if err != nil {
		log.Fatalf("failed to fetch non-identified files: %v", err)
	}
	if resp.StatusCode() != 200 {
		log.Fatalf("failed to fetch non-identified files: %d", resp.StatusCode())
	}
	err = json.Unmarshal(resp.Body(), &files)
	if err != nil {
		log.Fatalf("failed to unmarshal response: %v", err)
	}
	return files.Files
}

func identifyFile(file File) FileInfo {
	// Get the actual file by its ID, save it in tmp folder
	resp, err := resty.R().Get(coordinatorURL + "/files/" + fmt.Sprintf("%d", file.ID))
	if err != nil {
		log.Fatalf("failed to fetch file %s: %v", file.Filename, err)
	}
	if resp.StatusCode() != 200 {
		log.Fatalf("failed to fetch file %s: %d", file.Filename, resp.StatusCode())
	}

	tmpfile, err := ioutil.TempFile("/tmp", "ident_")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err = tmpfile.Write(resp.Body()); err != nil {
		log.Fatal(err)
	}
	if err = tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(60)*time.Second)
	defer cancel()

	// Do FileInfo scan
	mtx.Lock()
	defer mtx.Unlock()
	path := tmpfile.Name()
	GetFileMimeType(ctx, path)
	GetFileDescription(ctx, path)

	fileInfo := FileInfo{
		Magic:    fi.Magic,
		SSDeep:   ParseSsdeepOutput(utils.RunCommand(ctx, "ssdeep", path)),
		TRiD:     ParseTRiDOutput(utils.RunCommand(ctx, "trid", path)),
		Exiftool: ParseExiftoolOutput(utils.RunCommand(ctx, "exiftool", path)),
	}

	return fileInfo
}
