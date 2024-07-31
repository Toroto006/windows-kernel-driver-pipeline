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

export interface VulnerableDriver {
    description: string;
    file: number;
    filename: string;
    id: number;
    origin: string;
    sha256: string;
}
  
export const columns: ColumnDef<VulnerableDriver>[] = [
  {
    accessorKey: "filename",
    header: ({ column }) => (
      <div className={cn("flex items-center space-x-2")}>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className="-ml-3 h-8 data-[state=open]:bg-accent"
          >
            <span>Filename</span>
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
  },
  {
    accessorKey: "origin",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Origin" />
    ),
  },
  {
    accessorKey: "description",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Description" />
    ),
  },
  {
    accessorKey: "sha256",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="SHA256" />
    ),
  },
  {
    accessorKey: "file",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Underlying File" />
    ),
  },
]
