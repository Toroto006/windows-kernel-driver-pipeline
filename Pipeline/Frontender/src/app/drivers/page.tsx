"use client";

import { NavBar } from "@/components/navbar";
import { allDrivers } from '@/components/data-fetcher';

import { columns } from "@/types/Driver"
import { DataTable } from "@/components/ui/data-table"

export default function DriversPage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <NavBar/>
      {/* center the table and give it a border */}
      {allDrivers().isLoading && <p>Loading...</p>}
      {allDrivers().isError && <p>Error: {allDrivers().isError}</p>}

      {allDrivers().drivers && 
        <div className="rounded-md">
          <DataTable columns={columns} data={allDrivers().drivers} filterBy="tag"
            columnVisibility={{ 
              'sha256': false,
              'sha1': false,
              'file': false,
              'og_file_id': false,
              'origin': false,
              'ida_ret_code': false,
            }}
          />
        </div>
      }
    </main>
  );
}
