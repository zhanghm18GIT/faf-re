"""Windows Job Object containment. No action occurs on import."""
import ctypes as c
import os
import time
import uuid

DWORD=c.c_uint32; HANDLE=c.c_void_p; SIZE=c.c_size_t; QWORD=c.c_uint64
class BasicLimit(c.Structure):
    _fields_=[('PerProcessUserTimeLimit',c.c_int64),('PerJobUserTimeLimit',c.c_int64),('LimitFlags',DWORD),
              ('MinimumWorkingSetSize',SIZE),('MaximumWorkingSetSize',SIZE),('ActiveProcessLimit',DWORD),
              ('Affinity',SIZE),('PriorityClass',DWORD),('SchedulingClass',DWORD)]
class IO(c.Structure):
    _fields_=[(x,QWORD) for x in ['ReadOperationCount','WriteOperationCount','OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount']]
class ExtendedLimit(c.Structure):
    _fields_=[('BasicLimitInformation',BasicLimit),('IoInfo',IO),('ProcessMemoryLimit',SIZE),('JobMemoryLimit',SIZE),('PeakProcessMemoryUsed',SIZE),('PeakJobMemoryUsed',SIZE)]
class Accounting(c.Structure):
    _fields_=[(x,c.c_int64) for x in ['TotalUserTime','TotalKernelTime','ThisPeriodTotalUserTime','ThisPeriodTotalKernelTime']]+[(x,DWORD) for x in ['TotalPageFaultCount','TotalProcesses','ActiveProcesses','TotalTerminatedProcesses']]

def kernel():
    if os.name!='nt':raise RuntimeError('Windows Job Objects require Windows')
    k=c.WinDLL('kernel32',use_last_error=True)
    for name,args,result in [('CreateJobObjectW',[HANDLE,c.c_wchar_p],HANDLE),('OpenJobObjectW',[DWORD,c.c_int,c.c_wchar_p],HANDLE),
            ('SetInformationJobObject',[HANDLE,c.c_int,HANDLE,DWORD],c.c_int),('QueryInformationJobObject',[HANDLE,c.c_int,HANDLE,DWORD,HANDLE],c.c_int),
            ('AssignProcessToJobObject',[HANDLE,HANDLE],c.c_int),('TerminateJobObject',[HANDLE,DWORD],c.c_int),
            ('GetCurrentProcess',[],HANDLE),('CloseHandle',[HANDLE],c.c_int)]:
        f=getattr(k,name);f.argtypes=args;f.restype=result
    return k

def check(ok,label):
    if not ok:raise OSError(c.get_last_error(),label)

class WindowsJob:
    def __init__(self):
        self.k=kernel();self.name='Local\\faf-fresh-'+uuid.uuid4().hex
        self.handle=self.k.CreateJobObjectW(None,self.name);check(self.handle,'CreateJobObjectW')
        info=ExtendedLimit();info.BasicLimitInformation.LimitFlags=0x2000 # KILL_ON_JOB_CLOSE
        try:check(self.k.SetInformationJobObject(self.handle,9,c.byref(info),c.sizeof(info)),'SetInformationJobObject')
        except BaseException:self.close();raise
    def active(self):
        info=Accounting();check(self.k.QueryInformationJobObject(self.handle,1,c.byref(info),c.sizeof(info),None),'QueryInformationJobObject')
        return info.ActiveProcesses
    def terminate(self):
        check(self.k.TerminateJobObject(self.handle,1),'TerminateJobObject')
        until=time.monotonic()+5
        while self.active():
            if time.monotonic()>=until:return False
            time.sleep(0.02)
        return True
    def close(self):
        if self.handle:
            h,self.handle=self.handle,None;check(self.k.CloseHandle(h),'CloseHandle job')

def join_named_job(name):
    if not name.startswith('Local\\faf-fresh-'):raise RuntimeError('Unexpected job name')
    k=kernel();h=k.OpenJobObjectW(1,False,name);check(h,'OpenJobObjectW')
    try:check(k.AssignProcessToJobObject(h,k.GetCurrentProcess()),'AssignProcessToJobObject')
    finally:check(k.CloseHandle(h),'CloseHandle joined job')
