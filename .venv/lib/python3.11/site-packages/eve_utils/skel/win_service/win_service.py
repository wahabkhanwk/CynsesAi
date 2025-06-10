import win32serviceutil
import win32service
import win32event
import servicemanager

from eve_service import EveService


class EveWindowsService(win32serviceutil.ServiceFramework):
    _svc_name_ = "{$project_name}"
    _svc_display_name_ = "{$project_name} API"
    # _svc_description_ = "Service description goes here."  # TODO: replace with config or some such

    def __init__(self, args):
        self._eve = EveService()

        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))

        self._eve.start()

        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STOPPED,
                              (self._svc_name_, ''))

    def SvcStop(self):
        self._eve.stop()
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(EveWindowsService)
