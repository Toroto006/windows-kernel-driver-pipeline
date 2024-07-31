"use client";

import useSWR from 'swr'
import { DriverOverview, Driver } from '@/types/Driver'
import { PathingResult, Path } from '@/types/Pathing'
import { VulnerableDriver } from '@/types/KnownVulnerable'
import { FuzzingQueueElem } from '@/types/FuzzingQueue';

const fetcher = (input:string | URL | Request) => fetch(input).then(res => res.json())

const backendUrl = "http://COORDINATOR_IP:5000"
// TODO FIX the blocked: mixed content issue, i.e. make the backend serve https

export function allDrivers (): { drivers: DriverOverview[], isLoading: boolean, isError: any } {
  const { data, error, isLoading } = useSWR(`${backendUrl}/drivers`, fetcher)
  
  if (!isLoading && !error) {
    return {
      drivers: data.drivers,
      isLoading,
      isError: error
    }
  }

  return {
    drivers: [],
    isLoading,
    isError: error
  }
}

export function originDrivers (search:string): { drivers: DriverOverview[], isLoading: boolean, isError: any } {
  const { data, error, isLoading } = useSWR(`${backendUrl}/drivers-filter/origin/${search}`, fetcher)
  
  if (!isLoading && !error) {
    return {
      drivers: data.drivers,
      isLoading,
      isError: error
    }
  }

  return {
    drivers: [],
    isLoading,
    isError: error
  }
}

export function importDrivers (search:string): { drivers: DriverOverview[], isLoading: boolean, isError: any } {
    const { data, error, isLoading } = useSWR(`${backendUrl}/drivers-filter/imports/${search}`, fetcher)
    
    if (!isLoading && !error) {
      return {
        drivers: data.drivers,
        isLoading,
        isError: error
      }
    }

    return {
      drivers: [],
      isLoading,
      isError: error
    }
}

export function getDriver (id: number) : { driver: Driver, isLoading: boolean, isError: any }{
    const { data, error, isLoading } = useSWR(`${backendUrl}/drivers/${id}`, fetcher)
   
    if (!isLoading && !error) {
      return {
        driver: data.driver,
        isLoading,
        isError: false
      }
    }

    return {
      driver: data,
      isLoading,
      isError: true
    }
}

export function getPathing (id: number) : { pathing: PathingResult, isLoading: boolean, isError: any }{
  const { data, error, isLoading } = useSWR(`${backendUrl}/driver-paths/${id}`, fetcher)
 
  if (!isLoading && !error && data.path) {
    
    return {
      pathing: data.path,
      isLoading,
      isError: false
    }
  }

  return {
    pathing: data,
    isLoading,
    isError: true
  }
}

export function getPossibleTags () : { tags: string[], isLoading: boolean, isError: any }{
  const { data, error, isLoading } = useSWR(`${backendUrl}/driver-tags`, fetcher)
 
  if (!isLoading && !error && data.tags) {
    
    return {
      tags: data.tags,
      isLoading,
      isError: false
    }
  }

  return {
    tags: data,
    isLoading,
    isError: true
  }
}

export function getVulnerableDrivers () : { drivers: VulnerableDriver[], isLoading: boolean, isError: any }{
    const { data, error, isLoading } = useSWR(`${backendUrl}/known-vulnerable-list`, fetcher)
   
    if (!isLoading && !error && data.drivers) {
      
      return {
        drivers: data.drivers,
        isLoading,
        isError: false
      }
    }

    return {
      drivers: data,
      isLoading,
      isError: true
    }
}

export function fuzzingQueue () : { queued: FuzzingQueueElem[], done: FuzzingQueueElem[], running: FuzzingQueueElem[], isLoading: boolean, isError: any }{
  const { data, error, isLoading } = useSWR(`${backendUrl}/fuzzing-queue`, fetcher)
 
  if (!isLoading && !error && data.queued) {
    
    return {
      queued: data.queued,
      done: data.done.concat(data.errored),
      running: data.running,
      isLoading,
      isError: false
    }
  }

  return {
    queued: data,
    done: data,
    running: data,
    isLoading,
    isError: true
  }
}
