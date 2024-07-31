"use client";

import { NavBar } from "@/components/navbar";
import { getVulnerableDrivers } from '@/components/data-fetcher';

import { columns } from "@/types/KnownVulnerable"
import { DataTable } from "@/components/ui/data-table"

export default function DriversPage() {
    let knownVulnerableDrivers = getVulnerableDrivers().drivers;

  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <NavBar/>
      {/* center the table and give it a border */}
      {/* {isLoading && <p>Loading...</p>}
      {isError && <p>Error: {knownVulnerableDrivers}</p>} */}

      {knownVulnerableDrivers && 
        <div className="rounded-md">
          <DataTable columns={columns} tableTitle="Known Vulnerable List" data={knownVulnerableDrivers} filterBy="filename" />
        </div>
      }
    </main>
  );
}
