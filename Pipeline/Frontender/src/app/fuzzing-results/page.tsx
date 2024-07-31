"use client";

import { NavBar } from "@/components/navbar";
import { getDriver } from '@/components/data-fetcher';
import { Driver } from '@/types/Driver'
import DriverComponent from "@/components/ui/driver";
import { useSearchParams } from 'next/navigation'
 
export default function DriverFuzzingPage() {
  const searchParams = useSearchParams()
  const driverID = searchParams.get('id') ? parseInt(searchParams.get('id') as string) : -1;

  let driver: Driver | null = null;
  driver = getDriver(driverID).driver;
  let error: boolean = getDriver(driverID).isError;

  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <NavBar/>
      {/* center the table and give it a border */}
      {getDriver(driverID).isLoading && <p>Loading...</p>}
      {error && <p>Error in getting this specific driver!</p>}

      {!error && driver && 
        <div className="rounded-md">
          <DriverComponent driver={driver} />
        </div>
      }
    </main>
  );
}
