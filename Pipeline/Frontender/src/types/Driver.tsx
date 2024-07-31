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

type SigningDate = string;
type ValidFrom = string;
type ValidTo = string;

type Signer = {
  cert_issuer: string;
  cert_status: string;
  id: number;
  name: string;
  valid_from: ValidFrom;
  valid_to: ValidTo;
};

type Signature = {
  catalog: string;
  sign_result: number;
  id: number;
  signers: Signer[];
  signing_date: SigningDate;
};

type SignResults = {
  company: string;
  created_at: string;
  description: string;
  file_version: string;
  id: number;
  prod_version: string;
  product: string;
  signatures: Signature[];
  valid: boolean;
  verified: string;
};

type PathResults = {
  combined_sub_functions: number;
  created_at: string;
  handler_addrs: string;
  id: number;
  ret_code: number;
  type: string;
};

type StaticResults = {
  created_at: string;
  concat_dos_device_str: string;
  id: number;
  imphash: string;
  imports: string[];
  phys_mem: boolean;
  security_str: string | null;
};

type FuzzingResults = {
  id: number;
  payloads: number[]; // references to the payloads
  runtime: number;
  total_execs: number;
  p_coll: number; // probability of collision for binary paths
  total_reloads: number; 
  paths_total: number;
  bb_covered: number; // amount of basic blocks covered
  created_at: string;
};

export type Driver = {
  architecture: string;
  file: number;
  filename: string;
  fuzzing_results: FuzzingResults | null;
  id: number;
  path_results: PathResults | null;
  sha256: string;
  sha1: string;
  ssdeep: string;
  sign_results: SignResults | null;
  static_results: StaticResults | null;
  tag: string;
};

export type DriverOverview = {
    architecture: string;
    file: number;
    filename: string;
    id: number;
    sha1: string;
    sha256: string;
    tag: string;
    ida_ret_code: number;
    og_file_id: number;
    origin: string;
    verified: string;
    by: string;
  };

export const columns: ColumnDef<DriverOverview>[] = [
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
            <span>Driver Filename</span>
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
    cell: props => <a href={`/driver/?id=${props.row.original.id}`}>{props.row.original.filename}</a>
  },
  {
    accessorKey: "architecture",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Arch" />
    ),
    cell: props => props.row.original.architecture.replace("Arch.", ""),
  },
  {
    accessorKey: "tag",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Tagged as" />
    ),
  },
  {
    accessorKey: "origin",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Origin" />
    ),
  },
  {
    accessorKey: "verified",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Signature" />
    ),
    cell: props => {
      if (props.row.original.verified && props.row.original.verified === "Signed") {
        let res = "Signed"
        if (props.row.original.by != "n/a") {
          res += ": " + props.row.original.by
        }
        return res
      } else if (props.row.original.verified) {
        return props.row.original.verified.length > 15 ? props.row.original.verified.slice(0, 15) + "..." : props.row.original.verified
      } else {
        return "Unknown"
      }
    },
  },
  {
    accessorKey: "ida_ret_code",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="IDA Ret Code" />
    ),
  },
  {
    accessorKey: "sha256",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="SHA256" />
    ),
  },
  {
    accessorKey: "sha1",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="SHA1" />
    ),
  },
  {
    accessorKey: "og_file_id",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Original File ID" />
    ),
  },
  {
    accessorKey: "file",
    header: "Underlying File ID",
  },
]
