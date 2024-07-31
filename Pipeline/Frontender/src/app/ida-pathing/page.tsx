"use client";

import { NavBar } from "@/components/navbar";
import { getPathing } from '@/components/data-fetcher';
import { useSearchParams } from 'next/navigation'
import { PathingResult } from "@/types/Pathing";

import FunctionTree from "@/components/ida-pathing";

export default function PathingPage() {
  const searchParams = useSearchParams()
  const driverID = searchParams.get('id') ? parseInt(searchParams.get('id') as string) : -1;

  let pathing: PathingResult | null = null;
  pathing = getPathing(driverID).pathing;
  let error: boolean = getPathing(driverID).isError;

  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <NavBar/>
      {/* center the table and give it a border */}
      {getPathing(driverID).isLoading && <p>Loading...</p>}
      {!error && pathing &&
        <div className="rounded-md">
          <p>Type {pathing.type} return code {pathing.ret_code} at {pathing.created_at}.</p>
          <p>Total of {pathing.ioctl_comp.length} probable IOCTL codes found.</p>
        </div>
      }
      {!error && pathing &&
        <div className="rounded-md">
          <p>Following paths were found:</p>
          {pathing.handler_addrs &&
            <FunctionTree handlerAddrs={pathing.handler_addrs} paths={pathing.paths} />
          }
        </div>
      }
    </main>
  );
}
