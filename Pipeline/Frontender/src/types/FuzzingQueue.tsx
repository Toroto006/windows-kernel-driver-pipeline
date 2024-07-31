"use client"

import { ColumnDef } from "@tanstack/react-table"
import { DataTableColumnHeader } from "@/components/ui/column-header"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
  } from "@/components/ui/dropdown-menu"
import { ArrowDownIcon, ArrowUpIcon, CaretSortIcon } from "@radix-ui/react-icons"

export type FuzzingQueueElem = {
    driver: number;
    priority: number;
    max_runtime: number | null;
    max_last_crash: number | null;
    max_last_any: number | null;
    dos_device_str: string | null;
    seeds: number[];
    // the following are not used for adding new elements
    created_at: Date | null;
    finished_at: Date | null;
    id: number | null;
    state: string | null;
};

export const columns: ColumnDef<FuzzingQueueElem>[] = [
    {
      accessorKey: "driver_id",
      header: ({ column }) => (
        <div className={cn("flex items-center space-x-2")}>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="-ml-3 h-8 data-[state=open]:bg-accent"
            >
              <span>Driver ID</span>
              {column.getIsSorted() === "desc" ? (
                <ArrowDownIcon className="ml-2 h-4 w-4" />
              ) : column.getIsSorted() === "asc" ? (
                <ArrowUpIcon className="ml-2 h-4 w-4" />
              ) : (
                <CaretSortIcon className="ml-2 h-4 w-4" />
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuItem onClick={() => column.toggleSorting(false)}>
              <ArrowUpIcon className="mr-2 h-3.5 w-3.5 text-muted-foreground/70" />
              Asc
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => column.toggleSorting(true)}>
              <ArrowDownIcon className="mr-2 h-3.5 w-3.5 text-muted-foreground/70" />
              Desc
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      ),
      cell: props => <a href={`/driver/?id=${props.row.original.driver}`}>{props.row.original.driver}</a>
    },
    {
      accessorKey: "priority",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Priority" />
      ),
    },
    {
      accessorKey: "state",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="State" />
      ),
    },
    {
      accessorKey: "dos_device_str",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Used Device String" />
      ),
    },
    {
      accessorKey: "finished_at",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Finished" />
      ),
      cell: props => {
        if (props.row.original.created_at == null) {
          return "N/A";
        } else {
          const date = new Date(props.row.original.created_at);
          return date.toLocaleString();
        }
      }
    },
    {
      accessorKey: "created_at",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Created" />
      ),
      cell: props => {
        if (props.row.original.created_at == null) {
          return "N/A";
        } else {
          const date = new Date(props.row.original.created_at);
          return date.toLocaleString();
        }
      }
    },
    // {
    //   accessorKey: "og_file_id",
    //   header: ({ column }) => (
    //     <DataTableColumnHeader column={column} title="Original File ID" />
    //   ),
    // },
    // {
    //   accessorKey: "file",
    //   header: "Underlying File ID",
    // },
  ]
  

// FuzzingQueueElem creator, setting defaults
export function createFuzzingQueueElem(driver_id: number, priority: number = 0, max_runtime: number | null = 42800, max_last_crash: number | null = null, max_last_any: number | null = null, dos_device_str: string | null = null, seeds: number[] = []): FuzzingQueueElem {
    return {
        driver: driver_id,
        priority: priority,
        max_runtime: max_runtime,
        max_last_crash: max_last_crash,
        max_last_any: max_last_any,
        dos_device_str: dos_device_str,
        seeds: seeds,
        created_at: null,
        finished_at: null,
        id: null,
        state: null
    };
}
  