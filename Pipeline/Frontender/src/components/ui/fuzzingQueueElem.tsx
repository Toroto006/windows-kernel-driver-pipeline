import { FuzzingQueueElem } from "@/types/FuzzingQueue";
import {
    Card,
    CardContent,
    CardDescription,
    CardFooter,
    CardHeader,
    CardTitle,
  } from "@/components/ui/card"
  import { Input } from "@/components/ui/input"
  import { Label } from "@/components/ui/label"
  import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
  } from "@/components/ui/select"

// UI element showing the fuzzing queue element, allowing for input changes and value changes
export function FuzzingQueueElemUI(
    { queueElem, setQueueElem }: { queueElem: FuzzingQueueElem, setQueueElem: (queueElem: FuzzingQueueElem) => void }
) {
    return (
        <Card>
            <CardContent>
                <Label>Priority</Label>
                <Input type="number" value={queueElem.priority} onChange={(e) => setQueueElem({ ...queueElem, priority: parseInt(e.target.value) })} />
                <Label>Maximal Runtime</Label>
                <Input type="number" value={queueElem.max_runtime ? queueElem.max_runtime : ''} onChange={(e) => setQueueElem({ ...queueElem, max_runtime: parseInt(e.target.value) })} />
                <Label>Max. time for last Crash</Label>
                <Input type="number" value={queueElem.max_last_crash ? queueElem.max_last_crash : ''} onChange={(e) => setQueueElem({ ...queueElem, max_last_crash: parseInt(e.target.value) })} />
                <Label>Max. time for last any</Label>
                <Input type="number" value={queueElem.max_last_any ? queueElem.max_last_any : ''} onChange={(e) => setQueueElem({ ...queueElem, max_last_any: parseInt(e.target.value) })} />
                <Label>Dos Device String (full)</Label>
                <Input type="text" value={queueElem.dos_device_str ? queueElem.dos_device_str : ''} onChange={(e) => setQueueElem({ ...queueElem, dos_device_str: e.target.value })} />
            </CardContent>
        </Card>
    );
};