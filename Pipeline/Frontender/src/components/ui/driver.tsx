import {
    Copy,
    MoreVertical,
  } from "lucide-react"
  import { Button } from "@/components/ui/button"
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from "@/components/ui/card"
  import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
  } from "@/components/ui/dropdown-menu"  
  import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
  import { Separator } from "@/components/ui/separator"
  import { Driver } from "@/types/Driver"
  import Link from 'next/link'
  import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
    DialogFooter,
    DialogClose,
  } from "@/components/ui/dialog"
  import { updateFilename, updateDriverTag, addFuzzingQueue } from "@/components/data-pusher"
  import { Input } from "@/components/ui/input"
  import { Label } from "@/components/ui/label"
  import { useState } from "react"
  import { useToast } from "@/components/ui/use-toast"
  import { getPossibleTags } from "@/components/data-fetcher"
  import { createFuzzingQueueElem } from "@/types/FuzzingQueue"
  import { FuzzingQueueElemUI } from "@/components/ui/fuzzingQueueElem"
  
  interface DriverProps {
    driver: Driver;
  }

  export default function DriverComponent({ driver }: DriverProps) {
    let [newFilename, setNewFilename] = useState(driver.filename);
    let [newTag, setNewTag] = useState(driver.tag);

    const { toast } = useToast();

    let possibleTags = getPossibleTags().tags;

    let [fuzzQueueElm, setQueueElem] = useState(createFuzzingQueueElem(driver.id));

    return (
      <Card className="overflow-hidden">
        <CardHeader className="flex flex-row items-start bg-muted/50">
          <div className="grid gap-0.5">
            <CardTitle className="group flex items-center gap-2 text-lg">
              {newFilename}
              <Button
                size="icon"
                variant="outline"
                className="h-6 w-6 opacity-0 transition-opacity group-hover:opacity-100"
                onClick={() => navigator.clipboard.writeText(driver.id.toString())}
              >
                <Copy className="h-3 w-3" />
              </Button>
            </CardTitle>
            <CardDescription>{newTag} | {driver.architecture.replace("Arch.", "")} </CardDescription>
          </div>
          <div className="ml-auto flex items-center gap-1">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button size="icon" variant="outline" className="h-8 w-8">
                    <MoreVertical className="h-3.5 w-3.5" />
                    <span className="sr-only">More</span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <Dialog>
                    <DialogTrigger asChild>
                      <DropdownMenuItem onSelect={(e) => e.preventDefault()}>
                        Set Tag
                      </DropdownMenuItem>
                    </DialogTrigger>
                    <DialogContent className="sm:max-w-[325px]">
                      <DialogHeader>
                        <DialogTitle>Set Tag</DialogTitle>
                        <DialogDescription>
                          Set tag for the driver. Click save when you're done (not all options are possible).
                        </DialogDescription>
                      </DialogHeader>
                        <RadioGroup defaultValue={newTag} className="items-center">
                          {possibleTags !== undefined && possibleTags.map((tag) => (
                            <div className="flex items-center space-x-2">
                              <RadioGroupItem value={tag} id={tag} onClick={() => setNewTag(tag)}/>
                              <Label htmlFor={tag}>{tag}</Label>
                            </div>
                          ))}
                        </RadioGroup>
                      <DialogFooter>
                      <DialogClose asChild>
                        <Button type="submit" onClick={() => {
                            updateDriverTag(driver.id, newTag).then(res => {
                              if (res.status !== 200) {
                                  console.error(`Failed to update tag for driver ${driver.id}`);
                                  toast({
                                      title: "Failed to update driver tag",
                                      description: res.json(),
                                    })
                              } else {
                                  console.log(`Updated for driver ${driver.id} to ${newTag}`);
                                  toast({
                                      title: "Tag updated",
                                      description: `Tag for driver ${driver.id} updated to ${newTag}`
                                  })
                              }
                            }).catch(err => {
                              console.error(`Failed to update driver tag for file ${driver.id}`);
                              toast({
                                  title: "Failed to update driver tag",
                                  description: err,
                                })
                            });
                          }}>Save changes</Button>
                      </DialogClose>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>

                  <Dialog>
                    <DialogTrigger asChild>
                      <DropdownMenuItem onSelect={(e) => e.preventDefault()}>
                        Change Filename
                      </DropdownMenuItem>
                    </DialogTrigger>
                    <DialogContent className="sm:max-w-[525px]">
                      <DialogHeader>
                        <DialogTitle>Set Filename</DialogTitle>
                        <DialogDescription>
                          Make changes to the filename here. Click save when you're done.
                        </DialogDescription>
                      </DialogHeader>
                      <div className="grid gap-4 py-4">
                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="filename" className="text-right">
                            Filename
                          </Label>
                          <Input
                            id="filename"
                            defaultValue={newFilename}
                            className="col-span-3"
                            onChange={(e) => setNewFilename(e.target.value)}
                          />
                        </div>
                      </div>
                      <DialogFooter>
                      <DialogClose asChild>
                        <Button type="submit" onClick={() => {
                            updateFilename(driver.file, newFilename).then(res => {
                              if (res.status !== 200) {
                                  console.error(`Failed to update filename for file ${driver.file}`);
                                  toast({
                                      title: "Failed to update filename",
                                      description: res.statusText,
                                    })
                              } else {
                                  console.log(`Filename updated for file ${driver.file} to ${newFilename}`);
                                  toast({
                                      title: "Filename updated",
                                      description: `Filename for file ${driver.file} updated to ${newFilename}`
                                  })
                              }
                            }).catch(err => {
                              console.error(`Failed to update filename for file ${driver.file}`);
                              toast({
                                  title: "Failed to update filename",
                                  description: err,
                                })
                            });
                          }}>Save changes</Button>
                      </DialogClose>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>

                  <Dialog>
                    <DialogTrigger asChild>
                      <DropdownMenuItem onSelect={(e) => e.preventDefault()}>
                        Add to Fuzzing Queue
                      </DropdownMenuItem>
                    </DialogTrigger>
                    <DialogContent className="sm:max-w-[525px]">
                      <DialogHeader>
                        <DialogTitle>Add to Fuzzing Queue</DialogTitle>
                        <DialogDescription>
                          Add {driver.filename} ({driver.id}) to the fuzzing queue.
                        </DialogDescription>
                      </DialogHeader>
                      <FuzzingQueueElemUI queueElem={fuzzQueueElm} setQueueElem={setQueueElem} />
                      <DialogFooter>
                      <DialogClose asChild>
                        <Button type="submit" onClick={() => {
                            addFuzzingQueue(fuzzQueueElm).then(res => {
                              if (res.status !== 200) {
                                  console.error(`Failed to add driver ${driver.id} to fuzzing queue`);
                                  toast({
                                      title: "Failed to add to fuzzing queue",
                                      description: res.statusText,
                                    })
                              }
                            });
                          }}>Add to queue</Button>
                      </DialogClose>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>

                  <DropdownMenuItem>
                    {/* TODO should somehow take this value from an ENV variable */}
                    <Link href={`http://COORDINATOR_IP:5000/files/${driver.file}`}>
                      Download File
                    </Link>
                  </DropdownMenuItem>

                  {/* <DropdownMenuSeparator /> */}
                  {/* <DropdownMenuItem>Trash</DropdownMenuItem> */}
                </DropdownMenuContent>
              </DropdownMenu>
          </div>
        </CardHeader>
        <CardContent className="p-6 text-sm">
          <div className="grid gap-3">
            <div className="font-semibold">Driver Details</div>
            <ul className="grid gap-3">
              <li className="flex items-center justify-between">
                <span className="text-muted-foreground">
                  SHA256: {driver.sha256}
                </span>
              </li>
              <li className="flex items-center justify-between">
                <span className="text-muted-foreground">
                  SHA1: {driver.sha1}
                </span>
              </li>
              {driver.static_results && ( 
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    ImpHash: {driver.static_results.imphash}
                  </span>
                </li>
              )}
              <li className="flex items-center justify-between">
                <span className="text-muted-foreground">
                  ssdeep: {driver.ssdeep}
                </span>
              </li>
              {/* <li className="flex items-center justify-between">
                <span className="text-muted-foreground">
                  Driver ID: {driver.id}
                </span>
              </li> */}
              <li className="flex items-center justify-between">
                <span className="text-muted-foreground">
                  File ID: {driver.file}
                </span>
              </li>
            </ul>
          </div>
          <Separator className="my-2" />
          {/* Render optional results */}
          
          {driver.static_results && (
            <div className="grid gap-3">
              <div className="font-semibold">Static Analysis</div>
              <ul className="grid gap-3">
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    Imports: {driver.static_results.imports.join(", ")}
                  </span>

                  {/* Add the list of imports, but only the first 15 */}
                  {/* <span className="text-muted-foreground">
                    Imports: {driver.static_results.imports.slice(0, 15).join(", ")} {driver.static_results.imports.length > 15 ? "..." : ""}
                  </span> */}
                </li>
                {driver.static_results.concat_dos_device_str && (
                  <li className="flex items-center justify-between">
                    <span className="text-muted-foreground">
                      {/* max 200 characters */}
                      Access Strings: {driver.static_results.concat_dos_device_str && driver.static_results.concat_dos_device_str.length > 200 ? driver.static_results.concat_dos_device_str.slice(0, 200) + "..." : driver.static_results.concat_dos_device_str}
                    </span>
                  </li>
                )}
                {driver.static_results.security_str && (
                <li className="flex items-center justify-between">
                  <span>
                      Security Strings: {driver.static_results.security_str}
                  </span>
                </li>
                )}
                {driver.static_results.phys_mem && (
                <li className="flex items-center justify-between">
                  <span className="text-green-500">
                      Phys. memory string PRESENT.
                  </span>
                </li>
                )}
                {/* <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    Created At: {driver.static_results.created_at}
                  </span>
                </li> */}
              </ul>
            </div>
          )}

          {driver.sign_results && <Separator className="my-2" />}
          {driver.sign_results && (
            <div className="grid gap-3">
              <div className="font-semibold">Certification</div>
              <ul className="grid gap-3">
                <li className="flex items-center justify-between">
                  {driver.sign_results.valid && (
                    <span className="text-green-500">Verification status: {driver.sign_results.verified}</span>
                  )}
                  {!driver.sign_results.valid && driver.sign_results.verified == "Unsigned" && (
                    <span className="text-red-500">Verification status: {driver.sign_results.verified}</span>
                  )}
                  {!driver.sign_results.valid && driver.sign_results.verified !== "Unsigned" && (
                    <span className="text-muted-foreground">Verification status: {driver.sign_results.verified}</span>
                  )}
                </li>
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    Company: {driver.sign_results.company}
                  </span>
                </li>
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    Description: {driver.sign_results.description}
                  </span>
                </li>
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    File Version: {driver.sign_results.file_version}
                  </span>
                </li>
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    Product Version: {driver.sign_results.prod_version}
                  </span>
                </li>
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    Product: {driver.sign_results.product}
                  </span>
                </li>
                {/* <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    Created At: {driver.sign_results.created_at}
                  </span>
                </li> */}
              </ul>
              {/* list for all signatures the signers name */}
              {driver.sign_results.valid && (
              <div>
                <div>Signatures chains:</div>
                <ul className="grid gap-3">
                  {driver.sign_results.signatures.map((signature) => (
                    <li key={signature.id} className="flex items-center justify-between">
                      <span className="text-muted-foreground">
                        {signature.signers.map((signer) => signer.name).join(", ")} | {signature.signing_date}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
              )}
            </div>
          )}

          {driver.path_results && <Separator className="my-2" />}
          {driver.path_results && (
            <div className="grid gap-3">
              <div className="font-semibold">Pathfinder Results</div>
              <ul className="grid gap-3">
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                  <Link href={`/ida-pathing?id=${driver.id}`}>
                    Type {driver.path_results.type} and {driver.path_results.handler_addrs.length > 3 && driver.path_results.ret_code > 100 ? (
                      "paths starting from: " + driver.path_results.handler_addrs
                    ) : "no paths found."}
                    </Link>
                  </span>
                </li>
                {/* TODO add a set of reachable functions:{driver.path_results.ret_code > 100 && (
                <li>
                  <span>Reachable Functions: {}</span>
                </li>
                )} */}
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    Combined sub functions: {driver.path_results.combined_sub_functions}
                  </span>
                </li>
              </ul>
            </div>
          )}

          {driver.fuzzing_results && <Separator className="my-2" />}
          {driver.fuzzing_results && (
            <div className="grid gap-3">
              <div className="font-semibold">Fuzzing Results</div>
              <ul className="grid gap-3">
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    Fuzzing stats: {(Math.round(driver.fuzzing_results.runtime * 10 / (60*60))/10).toFixed(1)} hours runtime, {driver.fuzzing_results.total_execs} total executions
                  </span>
                </li>
                <li className="flex items-center justify-between">
                  <span className="text-muted-foreground">
                    {(Math.round(driver.fuzzing_results.p_coll * 100) / 100).toFixed(2)}% probability of collision, {driver.fuzzing_results.bb_covered} basic blocks and {driver.fuzzing_results.paths_total} paths covered in last run.
                  </span>
                </li>
              </ul>
            </div>
          )}
        </CardContent>
        {/* <CardFooter className="flex flex-row items-center border-t bg-muted/50 px-6 py-3">
          <div className="text-xs text-muted-foreground">
            Updated <time dateTime={driver.updated_at}>{driver.updated_at}</time>
          </div>
        </CardFooter> */}
      </Card>
    )
  }
  