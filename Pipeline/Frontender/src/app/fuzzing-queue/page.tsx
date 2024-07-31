"use client";

import { NavBar } from "@/components/navbar";
import { fuzzingQueue } from '@/components/data-fetcher';

import { DataTable } from "@/components/ui/data-table"
import { columns, FuzzingQueueElem } from "@/types/FuzzingQueue"

export default function FuzzingQueuePage() {
    let fuzzingQueued: FuzzingQueueElem[] | null = null;
    let fuzzingDone: FuzzingQueueElem[] | null = null;
    let fuzzingRunning: FuzzingQueueElem[] | null = null;
    let res = fuzzingQueue();
    if (!res.isError) {
        fuzzingQueued = res.queued;
        fuzzingDone = res.done;
        fuzzingRunning = res.running;
    } else {
        console.error(res.isError);
    }

  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
        <NavBar/>
        {/* center the table and give it a border */}
        {!res.isError && !fuzzingQueued && <p>Loading...</p>}
        {res.isError && <p>Error: {res.isError}</p>}

        {/* Fuzzing currently running */}
        {!res.isError && fuzzingRunning && fuzzingRunning.length === 0 && <p>No fuzzing jobs currently running.</p>}
        {!res.isError && fuzzingRunning && fuzzingRunning.length > 0 &&
            <div className="rounded-md">
            <DataTable columns={columns} data={fuzzingRunning}
                //filterBy="tag"
                tableTitle="Fuzzing running"
                columnVisibility={{ 
                    finished_at: false,
                    state: false,
                    created_at: false,
                }}
            />
            </div>
        }

        {/* Fuzzing done */}
        {!res.isError && fuzzingDone && fuzzingDone.length === 0 && <p>No fuzzing jobs done.</p>}
        {!res.isError && fuzzingDone && fuzzingDone.length > 0 &&
            <div className="rounded-md">
            <DataTable columns={columns} data={fuzzingDone}
                //filterBy="tag"
                tableTitle="Fuzzing done"
                columnVisibility={{ 
                    finished_at: true,
                    state: true,
                    created_at: false,
                }}
            />
            </div>
        }
    
        {/* Fuzzing queue*/}
        {!res.isError && fuzzingQueued && fuzzingQueued.length === 0 && <p>No fuzzing jobs queued.</p>}
        {!res.isError && fuzzingQueued && fuzzingQueued.length > 0 &&
        <div className="rounded-md">
            <DataTable columns={columns} data={fuzzingQueued}
            tableTitle="Fuzzing queue"
            //filterBy="tag"
            columnVisibility={{ 
                driver: true,
                finished_at: false,
                state: false,
                created_at: false,
            }}
            />
        </div>
        }
    </main>
  );
}
