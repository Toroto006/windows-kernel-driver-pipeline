import { NavBar } from "@/components/navbar";
import DriverComponent from "@/components/ui/driver";
import { getDriver } from "@/components/data-fetcher2";

import { allDrivers } from '@/components/data-fetcher';

const testID = 100;

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <NavBar/>
      
    </main>
  );
}
