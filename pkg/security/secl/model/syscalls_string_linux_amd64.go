// Code generated by "stringer -type Syscall -output pkg/security/secl/model/syscalls_string_linux_amd64.go pkg/security/secl/model/syscalls_linux_amd64.go"; DO NOT EDIT.

package model

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[SysRead-0]
	_ = x[SysWrite-1]
	_ = x[SysOpen-2]
	_ = x[SysClose-3]
	_ = x[SysStat-4]
	_ = x[SysFstat-5]
	_ = x[SysLstat-6]
	_ = x[SysPoll-7]
	_ = x[SysLseek-8]
	_ = x[SysMmap-9]
	_ = x[SysMprotect-10]
	_ = x[SysMunmap-11]
	_ = x[SysBrk-12]
	_ = x[SysRtSigaction-13]
	_ = x[SysRtSigprocmask-14]
	_ = x[SysRtSigreturn-15]
	_ = x[SysIoctl-16]
	_ = x[SysPread64-17]
	_ = x[SysPwrite64-18]
	_ = x[SysReadv-19]
	_ = x[SysWritev-20]
	_ = x[SysAccess-21]
	_ = x[SysPipe-22]
	_ = x[SysSelect-23]
	_ = x[SysSchedYield-24]
	_ = x[SysMremap-25]
	_ = x[SysMsync-26]
	_ = x[SysMincore-27]
	_ = x[SysMadvise-28]
	_ = x[SysShmget-29]
	_ = x[SysShmat-30]
	_ = x[SysShmctl-31]
	_ = x[SysDup-32]
	_ = x[SysDup2-33]
	_ = x[SysPause-34]
	_ = x[SysNanosleep-35]
	_ = x[SysGetitimer-36]
	_ = x[SysAlarm-37]
	_ = x[SysSetitimer-38]
	_ = x[SysGetpid-39]
	_ = x[SysSendfile-40]
	_ = x[SysSocket-41]
	_ = x[SysConnect-42]
	_ = x[SysAccept-43]
	_ = x[SysSendto-44]
	_ = x[SysRecvfrom-45]
	_ = x[SysSendmsg-46]
	_ = x[SysRecvmsg-47]
	_ = x[SysShutdown-48]
	_ = x[SysBind-49]
	_ = x[SysListen-50]
	_ = x[SysGetsockname-51]
	_ = x[SysGetpeername-52]
	_ = x[SysSocketpair-53]
	_ = x[SysSetsockopt-54]
	_ = x[SysGetsockopt-55]
	_ = x[SysClone-56]
	_ = x[SysFork-57]
	_ = x[SysVfork-58]
	_ = x[SysExecve-59]
	_ = x[SysExit-60]
	_ = x[SysWait4-61]
	_ = x[SysKill-62]
	_ = x[SysUname-63]
	_ = x[SysSemget-64]
	_ = x[SysSemop-65]
	_ = x[SysSemctl-66]
	_ = x[SysShmdt-67]
	_ = x[SysMsgget-68]
	_ = x[SysMsgsnd-69]
	_ = x[SysMsgrcv-70]
	_ = x[SysMsgctl-71]
	_ = x[SysFcntl-72]
	_ = x[SysFlock-73]
	_ = x[SysFsync-74]
	_ = x[SysFdatasync-75]
	_ = x[SysTruncate-76]
	_ = x[SysFtruncate-77]
	_ = x[SysGetdents-78]
	_ = x[SysGetcwd-79]
	_ = x[SysChdir-80]
	_ = x[SysFchdir-81]
	_ = x[SysRename-82]
	_ = x[SysMkdir-83]
	_ = x[SysRmdir-84]
	_ = x[SysCreat-85]
	_ = x[SysLink-86]
	_ = x[SysUnlink-87]
	_ = x[SysSymlink-88]
	_ = x[SysReadlink-89]
	_ = x[SysChmod-90]
	_ = x[SysFchmod-91]
	_ = x[SysChown-92]
	_ = x[SysFchown-93]
	_ = x[SysLchown-94]
	_ = x[SysUmask-95]
	_ = x[SysGettimeofday-96]
	_ = x[SysGetrlimit-97]
	_ = x[SysGetrusage-98]
	_ = x[SysSysinfo-99]
	_ = x[SysTimes-100]
	_ = x[SysPtrace-101]
	_ = x[SysGetuid-102]
	_ = x[SysSyslog-103]
	_ = x[SysGetgid-104]
	_ = x[SysSetuid-105]
	_ = x[SysSetgid-106]
	_ = x[SysGeteuid-107]
	_ = x[SysGetegid-108]
	_ = x[SysSetpgid-109]
	_ = x[SysGetppid-110]
	_ = x[SysGetpgrp-111]
	_ = x[SysSetsid-112]
	_ = x[SysSetreuid-113]
	_ = x[SysSetregid-114]
	_ = x[SysGetgroups-115]
	_ = x[SysSetgroups-116]
	_ = x[SysSetresuid-117]
	_ = x[SysGetresuid-118]
	_ = x[SysSetresgid-119]
	_ = x[SysGetresgid-120]
	_ = x[SysGetpgid-121]
	_ = x[SysSetfsuid-122]
	_ = x[SysSetfsgid-123]
	_ = x[SysGetsid-124]
	_ = x[SysCapget-125]
	_ = x[SysCapset-126]
	_ = x[SysRtSigpending-127]
	_ = x[SysRtSigtimedwait-128]
	_ = x[SysRtSigqueueinfo-129]
	_ = x[SysRtSigsuspend-130]
	_ = x[SysSigaltstack-131]
	_ = x[SysUtime-132]
	_ = x[SysMknod-133]
	_ = x[SysUselib-134]
	_ = x[SysPersonality-135]
	_ = x[SysUstat-136]
	_ = x[SysStatfs-137]
	_ = x[SysFstatfs-138]
	_ = x[SysSysfs-139]
	_ = x[SysGetpriority-140]
	_ = x[SysSetpriority-141]
	_ = x[SysSchedSetparam-142]
	_ = x[SysSchedGetparam-143]
	_ = x[SysSchedSetscheduler-144]
	_ = x[SysSchedGetscheduler-145]
	_ = x[SysSchedGetPriorityMax-146]
	_ = x[SysSchedGetPriorityMin-147]
	_ = x[SysSchedRrGetInterval-148]
	_ = x[SysMlock-149]
	_ = x[SysMunlock-150]
	_ = x[SysMlockall-151]
	_ = x[SysMunlockall-152]
	_ = x[SysVhangup-153]
	_ = x[SysModifyLdt-154]
	_ = x[SysPivotRoot-155]
	_ = x[SysSysctl-156]
	_ = x[SysPrctl-157]
	_ = x[SysArchPrctl-158]
	_ = x[SysAdjtimex-159]
	_ = x[SysSetrlimit-160]
	_ = x[SysChroot-161]
	_ = x[SysSync-162]
	_ = x[SysAcct-163]
	_ = x[SysSettimeofday-164]
	_ = x[SysMount-165]
	_ = x[SysUmount2-166]
	_ = x[SysSwapon-167]
	_ = x[SysSwapoff-168]
	_ = x[SysReboot-169]
	_ = x[SysSethostname-170]
	_ = x[SysSetdomainname-171]
	_ = x[SysIopl-172]
	_ = x[SysIoperm-173]
	_ = x[SysCreateModule-174]
	_ = x[SysInitModule-175]
	_ = x[SysDeleteModule-176]
	_ = x[SysGetKernelSyms-177]
	_ = x[SysQueryModule-178]
	_ = x[SysQuotactl-179]
	_ = x[SysNfsservctl-180]
	_ = x[SysGetpmsg-181]
	_ = x[SysPutpmsg-182]
	_ = x[SysAfsSyscall-183]
	_ = x[SysTuxcall-184]
	_ = x[SysSecurity-185]
	_ = x[SysGettid-186]
	_ = x[SysReadahead-187]
	_ = x[SysSetxattr-188]
	_ = x[SysLsetxattr-189]
	_ = x[SysFsetxattr-190]
	_ = x[SysGetxattr-191]
	_ = x[SysLgetxattr-192]
	_ = x[SysFgetxattr-193]
	_ = x[SysListxattr-194]
	_ = x[SysLlistxattr-195]
	_ = x[SysFlistxattr-196]
	_ = x[SysRemovexattr-197]
	_ = x[SysLremovexattr-198]
	_ = x[SysFremovexattr-199]
	_ = x[SysTkill-200]
	_ = x[SysTime-201]
	_ = x[SysFutex-202]
	_ = x[SysSchedSetaffinity-203]
	_ = x[SysSchedGetaffinity-204]
	_ = x[SysSetThreadArea-205]
	_ = x[SysIoSetup-206]
	_ = x[SysIoDestroy-207]
	_ = x[SysIoGetevents-208]
	_ = x[SysIoSubmit-209]
	_ = x[SysIoCancel-210]
	_ = x[SysGetThreadArea-211]
	_ = x[SysLookupDcookie-212]
	_ = x[SysEpollCreate-213]
	_ = x[SysEpollCtlOld-214]
	_ = x[SysEpollWaitOld-215]
	_ = x[SysRemapFilePages-216]
	_ = x[SysGetdents64-217]
	_ = x[SysSetTidAddress-218]
	_ = x[SysRestartSyscall-219]
	_ = x[SysSemtimedop-220]
	_ = x[SysFadvise64-221]
	_ = x[SysTimerCreate-222]
	_ = x[SysTimerSettime-223]
	_ = x[SysTimerGettime-224]
	_ = x[SysTimerGetoverrun-225]
	_ = x[SysTimerDelete-226]
	_ = x[SysClockSettime-227]
	_ = x[SysClockGettime-228]
	_ = x[SysClockGetres-229]
	_ = x[SysClockNanosleep-230]
	_ = x[SysExitGroup-231]
	_ = x[SysEpollWait-232]
	_ = x[SysEpollCtl-233]
	_ = x[SysTgkill-234]
	_ = x[SysUtimes-235]
	_ = x[SysVserver-236]
	_ = x[SysMbind-237]
	_ = x[SysSetMempolicy-238]
	_ = x[SysGetMempolicy-239]
	_ = x[SysMqOpen-240]
	_ = x[SysMqUnlink-241]
	_ = x[SysMqTimedsend-242]
	_ = x[SysMqTimedreceive-243]
	_ = x[SysMqNotify-244]
	_ = x[SysMqGetsetattr-245]
	_ = x[SysKexecLoad-246]
	_ = x[SysWaitid-247]
	_ = x[SysAddKey-248]
	_ = x[SysRequestKey-249]
	_ = x[SysKeyctl-250]
	_ = x[SysIoprioSet-251]
	_ = x[SysIoprioGet-252]
	_ = x[SysInotifyInit-253]
	_ = x[SysInotifyAddWatch-254]
	_ = x[SysInotifyRmWatch-255]
	_ = x[SysMigratePages-256]
	_ = x[SysOpenat-257]
	_ = x[SysMkdirat-258]
	_ = x[SysMknodat-259]
	_ = x[SysFchownat-260]
	_ = x[SysFutimesat-261]
	_ = x[SysNewfstatat-262]
	_ = x[SysUnlinkat-263]
	_ = x[SysRenameat-264]
	_ = x[SysLinkat-265]
	_ = x[SysSymlinkat-266]
	_ = x[SysReadlinkat-267]
	_ = x[SysFchmodat-268]
	_ = x[SysFaccessat-269]
	_ = x[SysPselect6-270]
	_ = x[SysPpoll-271]
	_ = x[SysUnshare-272]
	_ = x[SysSetRobustList-273]
	_ = x[SysGetRobustList-274]
	_ = x[SysSplice-275]
	_ = x[SysTee-276]
	_ = x[SysSyncFileRange-277]
	_ = x[SysVmsplice-278]
	_ = x[SysMovePages-279]
	_ = x[SysUtimensat-280]
	_ = x[SysEpollPwait-281]
	_ = x[SysSignalfd-282]
	_ = x[SysTimerfdCreate-283]
	_ = x[SysEventfd-284]
	_ = x[SysFallocate-285]
	_ = x[SysTimerfdSettime-286]
	_ = x[SysTimerfdGettime-287]
	_ = x[SysAccept4-288]
	_ = x[SysSignalfd4-289]
	_ = x[SysEventfd2-290]
	_ = x[SysEpollCreate1-291]
	_ = x[SysDup3-292]
	_ = x[SysPipe2-293]
	_ = x[SysInotifyInit1-294]
	_ = x[SysPreadv-295]
	_ = x[SysPwritev-296]
	_ = x[SysRtTgsigqueueinfo-297]
	_ = x[SysPerfEventOpen-298]
	_ = x[SysRecvmmsg-299]
	_ = x[SysFanotifyInit-300]
	_ = x[SysFanotifyMark-301]
	_ = x[SysPrlimit64-302]
	_ = x[SysNameToHandleAt-303]
	_ = x[SysOpenByHandleAt-304]
	_ = x[SysClockAdjtime-305]
	_ = x[SysSyncfs-306]
	_ = x[SysSendmmsg-307]
	_ = x[SysSetns-308]
	_ = x[SysGetcpu-309]
	_ = x[SysProcessVmReadv-310]
	_ = x[SysProcessVmWritev-311]
	_ = x[SysKcmp-312]
	_ = x[SysFinitModule-313]
	_ = x[SysSchedSetattr-314]
	_ = x[SysSchedGetattr-315]
	_ = x[SysRenameat2-316]
	_ = x[SysSeccomp-317]
	_ = x[SysGetrandom-318]
	_ = x[SysMemfdCreate-319]
	_ = x[SysKexecFileLoad-320]
	_ = x[SysBpf-321]
	_ = x[SysExecveat-322]
	_ = x[SysUserfaultfd-323]
	_ = x[SysMembarrier-324]
	_ = x[SysMlock2-325]
	_ = x[SysCopyFileRange-326]
	_ = x[SysPreadv2-327]
	_ = x[SysPwritev2-328]
	_ = x[SysPkeyMprotect-329]
	_ = x[SysPkeyAlloc-330]
	_ = x[SysPkeyFree-331]
	_ = x[SysStatx-332]
	_ = x[SysIoPgetevents-333]
	_ = x[SysRseq-334]
	_ = x[SysPidfdSendSignal-424]
	_ = x[SysIoUringSetup-425]
	_ = x[SysIoUringEnter-426]
	_ = x[SysIoUringRegister-427]
	_ = x[SysOpenTree-428]
	_ = x[SysMoveMount-429]
	_ = x[SysFsopen-430]
	_ = x[SysFsconfig-431]
	_ = x[SysFsmount-432]
	_ = x[SysFspick-433]
	_ = x[SysPidfdOpen-434]
	_ = x[SysClone3-435]
	_ = x[SysCloseRange-436]
	_ = x[SysOpenat2-437]
	_ = x[SysPidfdGetfd-438]
	_ = x[SysFaccessat2-439]
	_ = x[SysProcessMadvise-440]
	_ = x[SysEpollPwait2-441]
	_ = x[SysMountSetattr-442]
	_ = x[SysQuotactlFd-443]
	_ = x[SysLandlockCreateRuleset-444]
	_ = x[SysLandlockAddRule-445]
	_ = x[SysLandlockRestrictSelf-446]
	_ = x[SysMemfdSecret-447]
	_ = x[SysProcessMrelease-448]
	_ = x[SysFutexWaitv-449]
	_ = x[SysSetMempolicyHomeNode-450]
}

const (
	_Syscall_name_0 = "SysReadSysWriteSysOpenSysCloseSysStatSysFstatSysLstatSysPollSysLseekSysMmapSysMprotectSysMunmapSysBrkSysRtSigactionSysRtSigprocmaskSysRtSigreturnSysIoctlSysPread64SysPwrite64SysReadvSysWritevSysAccessSysPipeSysSelectSysSchedYieldSysMremapSysMsyncSysMincoreSysMadviseSysShmgetSysShmatSysShmctlSysDupSysDup2SysPauseSysNanosleepSysGetitimerSysAlarmSysSetitimerSysGetpidSysSendfileSysSocketSysConnectSysAcceptSysSendtoSysRecvfromSysSendmsgSysRecvmsgSysShutdownSysBindSysListenSysGetsocknameSysGetpeernameSysSocketpairSysSetsockoptSysGetsockoptSysCloneSysForkSysVforkSysExecveSysExitSysWait4SysKillSysUnameSysSemgetSysSemopSysSemctlSysShmdtSysMsggetSysMsgsndSysMsgrcvSysMsgctlSysFcntlSysFlockSysFsyncSysFdatasyncSysTruncateSysFtruncateSysGetdentsSysGetcwdSysChdirSysFchdirSysRenameSysMkdirSysRmdirSysCreatSysLinkSysUnlinkSysSymlinkSysReadlinkSysChmodSysFchmodSysChownSysFchownSysLchownSysUmaskSysGettimeofdaySysGetrlimitSysGetrusageSysSysinfoSysTimesSysPtraceSysGetuidSysSyslogSysGetgidSysSetuidSysSetgidSysGeteuidSysGetegidSysSetpgidSysGetppidSysGetpgrpSysSetsidSysSetreuidSysSetregidSysGetgroupsSysSetgroupsSysSetresuidSysGetresuidSysSetresgidSysGetresgidSysGetpgidSysSetfsuidSysSetfsgidSysGetsidSysCapgetSysCapsetSysRtSigpendingSysRtSigtimedwaitSysRtSigqueueinfoSysRtSigsuspendSysSigaltstackSysUtimeSysMknodSysUselibSysPersonalitySysUstatSysStatfsSysFstatfsSysSysfsSysGetprioritySysSetprioritySysSchedSetparamSysSchedGetparamSysSchedSetschedulerSysSchedGetschedulerSysSchedGetPriorityMaxSysSchedGetPriorityMinSysSchedRrGetIntervalSysMlockSysMunlockSysMlockallSysMunlockallSysVhangupSysModifyLdtSysPivotRootSysSysctlSysPrctlSysArchPrctlSysAdjtimexSysSetrlimitSysChrootSysSyncSysAcctSysSettimeofdaySysMountSysUmount2SysSwaponSysSwapoffSysRebootSysSethostnameSysSetdomainnameSysIoplSysIopermSysCreateModuleSysInitModuleSysDeleteModuleSysGetKernelSymsSysQueryModuleSysQuotactlSysNfsservctlSysGetpmsgSysPutpmsgSysAfsSyscallSysTuxcallSysSecuritySysGettidSysReadaheadSysSetxattrSysLsetxattrSysFsetxattrSysGetxattrSysLgetxattrSysFgetxattrSysListxattrSysLlistxattrSysFlistxattrSysRemovexattrSysLremovexattrSysFremovexattrSysTkillSysTimeSysFutexSysSchedSetaffinitySysSchedGetaffinitySysSetThreadAreaSysIoSetupSysIoDestroySysIoGeteventsSysIoSubmitSysIoCancelSysGetThreadAreaSysLookupDcookieSysEpollCreateSysEpollCtlOldSysEpollWaitOldSysRemapFilePagesSysGetdents64SysSetTidAddressSysRestartSyscallSysSemtimedopSysFadvise64SysTimerCreateSysTimerSettimeSysTimerGettimeSysTimerGetoverrunSysTimerDeleteSysClockSettimeSysClockGettimeSysClockGetresSysClockNanosleepSysExitGroupSysEpollWaitSysEpollCtlSysTgkillSysUtimesSysVserverSysMbindSysSetMempolicySysGetMempolicySysMqOpenSysMqUnlinkSysMqTimedsendSysMqTimedreceiveSysMqNotifySysMqGetsetattrSysKexecLoadSysWaitidSysAddKeySysRequestKeySysKeyctlSysIoprioSetSysIoprioGetSysInotifyInitSysInotifyAddWatchSysInotifyRmWatchSysMigratePagesSysOpenatSysMkdiratSysMknodatSysFchownatSysFutimesatSysNewfstatatSysUnlinkatSysRenameatSysLinkatSysSymlinkatSysReadlinkatSysFchmodatSysFaccessatSysPselect6SysPpollSysUnshareSysSetRobustListSysGetRobustListSysSpliceSysTeeSysSyncFileRangeSysVmspliceSysMovePagesSysUtimensatSysEpollPwaitSysSignalfdSysTimerfdCreateSysEventfdSysFallocateSysTimerfdSettimeSysTimerfdGettimeSysAccept4SysSignalfd4SysEventfd2SysEpollCreate1SysDup3SysPipe2SysInotifyInit1SysPreadvSysPwritevSysRtTgsigqueueinfoSysPerfEventOpenSysRecvmmsgSysFanotifyInitSysFanotifyMarkSysPrlimit64SysNameToHandleAtSysOpenByHandleAtSysClockAdjtimeSysSyncfsSysSendmmsgSysSetnsSysGetcpuSysProcessVmReadvSysProcessVmWritevSysKcmpSysFinitModuleSysSchedSetattrSysSchedGetattrSysRenameat2SysSeccompSysGetrandomSysMemfdCreateSysKexecFileLoadSysBpfSysExecveatSysUserfaultfdSysMembarrierSysMlock2SysCopyFileRangeSysPreadv2SysPwritev2SysPkeyMprotectSysPkeyAllocSysPkeyFreeSysStatxSysIoPgeteventsSysRseq"
	_Syscall_name_1 = "SysPidfdSendSignalSysIoUringSetupSysIoUringEnterSysIoUringRegisterSysOpenTreeSysMoveMountSysFsopenSysFsconfigSysFsmountSysFspickSysPidfdOpenSysClone3SysCloseRangeSysOpenat2SysPidfdGetfdSysFaccessat2SysProcessMadviseSysEpollPwait2SysMountSetattrSysQuotactlFdSysLandlockCreateRulesetSysLandlockAddRuleSysLandlockRestrictSelfSysMemfdSecretSysProcessMreleaseSysFutexWaitvSysSetMempolicyHomeNode"
)

var (
	_Syscall_index_0 = [...]uint16{0, 7, 15, 22, 30, 37, 45, 53, 60, 68, 75, 86, 95, 101, 115, 131, 145, 153, 163, 174, 182, 191, 200, 207, 216, 229, 238, 246, 256, 266, 275, 283, 292, 298, 305, 313, 325, 337, 345, 357, 366, 377, 386, 396, 405, 414, 425, 435, 445, 456, 463, 472, 486, 500, 513, 526, 539, 547, 554, 562, 571, 578, 586, 593, 601, 610, 618, 627, 635, 644, 653, 662, 671, 679, 687, 695, 707, 718, 730, 741, 750, 758, 767, 776, 784, 792, 800, 807, 816, 826, 837, 845, 854, 862, 871, 880, 888, 903, 915, 927, 937, 945, 954, 963, 972, 981, 990, 999, 1009, 1019, 1029, 1039, 1049, 1058, 1069, 1080, 1092, 1104, 1116, 1128, 1140, 1152, 1162, 1173, 1184, 1193, 1202, 1211, 1226, 1243, 1260, 1275, 1289, 1297, 1305, 1314, 1328, 1336, 1345, 1355, 1363, 1377, 1391, 1407, 1423, 1443, 1463, 1485, 1507, 1528, 1536, 1546, 1557, 1570, 1580, 1592, 1604, 1613, 1621, 1633, 1644, 1656, 1665, 1672, 1679, 1694, 1702, 1712, 1721, 1731, 1740, 1754, 1770, 1777, 1786, 1801, 1814, 1829, 1845, 1859, 1870, 1883, 1893, 1903, 1916, 1926, 1937, 1946, 1958, 1969, 1981, 1993, 2004, 2016, 2028, 2040, 2053, 2066, 2080, 2095, 2110, 2118, 2125, 2133, 2152, 2171, 2187, 2197, 2209, 2223, 2234, 2245, 2261, 2277, 2291, 2305, 2320, 2337, 2350, 2366, 2383, 2396, 2408, 2422, 2437, 2452, 2470, 2484, 2499, 2514, 2528, 2545, 2557, 2569, 2580, 2589, 2598, 2608, 2616, 2631, 2646, 2655, 2666, 2680, 2697, 2708, 2723, 2735, 2744, 2753, 2766, 2775, 2787, 2799, 2813, 2831, 2848, 2863, 2872, 2882, 2892, 2903, 2915, 2928, 2939, 2950, 2959, 2971, 2984, 2995, 3007, 3018, 3026, 3036, 3052, 3068, 3077, 3083, 3099, 3110, 3122, 3134, 3147, 3158, 3174, 3184, 3196, 3213, 3230, 3240, 3252, 3263, 3278, 3285, 3293, 3308, 3317, 3327, 3346, 3362, 3373, 3388, 3403, 3415, 3432, 3449, 3464, 3473, 3484, 3492, 3501, 3518, 3536, 3543, 3557, 3572, 3587, 3599, 3609, 3621, 3635, 3651, 3657, 3668, 3682, 3695, 3704, 3720, 3730, 3741, 3756, 3768, 3779, 3787, 3802, 3809}
	_Syscall_index_1 = [...]uint16{0, 18, 33, 48, 66, 77, 89, 98, 109, 119, 128, 140, 149, 162, 172, 185, 198, 215, 229, 244, 257, 281, 299, 322, 336, 354, 367, 390}
)

func (i Syscall) String() string {
	switch {
	case 0 <= i && i <= 334:
		return _Syscall_name_0[_Syscall_index_0[i]:_Syscall_index_0[i+1]]
	case 424 <= i && i <= 450:
		i -= 424
		return _Syscall_name_1[_Syscall_index_1[i]:_Syscall_index_1[i+1]]
	default:
		return "Syscall(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
