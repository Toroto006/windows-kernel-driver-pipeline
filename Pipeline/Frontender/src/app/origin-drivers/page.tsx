"use client";

import { NavBar } from "@/components/navbar";
import { originDrivers } from '@/components/data-fetcher';
import { Input } from "@/components/ui/input"

import { columns } from "@/types/Driver"
import { DataTable } from "@/components/ui/data-table"
import { useState } from "react";

export default function DriversPage() {
  const [search, searchSetter] = useState("CDC");
  
  const drivers = originDrivers(search);

  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <NavBar/>
      <span className="font-bold">Drivers by Origin</span>
      <div className="flex items-center py-4">
            <Input
            placeholder="Drivers by Origin Search"
            value={search}
            onChange={(event) => {
                if (event.target.value.length > 0)
                  searchSetter(event.target.value)
                else {
                  searchSetter("CDC")
                }
              }
            }
            className="max-w-sm"
            />
      </div>

      {/* center the table and give it a border */}
      {drivers.isLoading && <p>Loading...</p>}
      {drivers.isError && <p>Error: {drivers.isError.toString()}</p>}

      {!drivers.isLoading && drivers.drivers.length > 0 && 
        <div className="rounded-md">
          <DataTable columns={columns} data={drivers.drivers}
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
