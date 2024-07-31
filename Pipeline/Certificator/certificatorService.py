# currently not used in the pipeline, idea was to make
# a service instead of having to run it manually after restarting the VM

import win32serviceutil
import win32service
import win32event
import servicemanager
import socket

from certificator import fetch_driver_signatures_todo, do_driver_certificat_checking
import time

class AppServerSvc (win32serviceutil.ServiceFramework):
    _svc_name_ = "CertificatorService"
    _svc_display_name_ = "Certificator Service"

    def __init__(self,args):
        self.isStopped = True
        win32serviceutil.ServiceFramework.__init__(self,args)
        self.hWaitStop = win32event.CreateEvent(None,0,0,None)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.isStopped = True
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_,''))
        self.isStopped = False
        self.main()

    def main(self):
        while not self.isStopped:
            drivers = fetch_driver_signatures_todo()
            if len(drivers) == 0: # We are done with one full iteration
                time.sleep(30)
                continue
            
            for driver in drivers:
                print(f"Doing {driver['filename']} ({driver['id']}) ... ", end="")
                do_driver_certificat_checking(driver)
                print("done")

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(AppServerSvc)