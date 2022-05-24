using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using static UtilDllImport;

class Util
{

    /// <summary>
    /// 최종수정 : 2022-04-09
    /// </summary>


    #region Account
    public class Account
    {
        public static string GetUserSid()
        {
            return WindowsIdentity.GetCurrent().User.ToString();
        }
    }
    #endregion

    #region Time
    public class Time
    {
        internal static string GetCurrentTimeStr()
        {
            DateTime DT = DateTime.Now;
            return DT.ToString("yyyy-MM-dd_HH-mm-ss");
        }
    }
    #endregion

    #region Path
    public class Path
    {
        public static string GetCurrentFolder()
        {
            string path = System.Reflection.Assembly.GetExecutingAssembly().Location;
            return System.IO.Path.GetDirectoryName(path);
        }
    }
    #endregion

    #region Registry

    public class Reg
    {
        public const string ValueRegDelete = "RegDelete";
        public const string RegDeleteAndWrite = "S_RegDeleteAndWrite";

        public enum RegValueKind
        {
            SZ = RegistryValueKind.String,
            EXPAND_SZ = RegistryValueKind.ExpandString,
            BINARY = RegistryValueKind.Binary,
            DWORD = RegistryValueKind.DWord,
            MULTI_SZ = RegistryValueKind.MultiString,
            QWORD = RegistryValueKind.QWord,
            Unknown = RegistryValueKind.Unknown,
            [ComVisible(false)]
            None = RegistryValueKind.None
        }

        private static RegistryKey RegPathCreate(ref string regPath) //ref를 쓴 이유 : Replace를 쓰기위해
        {
            RegistryKey rk = null;

            if (regPath.Contains("HKEY_CLASSES_ROOT"))
            {
                rk = RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot,
                                              Environment.Is64BitOperatingSystem
                                                  ? RegistryView.Registry64
                                                  : RegistryView.Registry32);
                regPath = regPath.Replace(@"HKEY_CLASSES_ROOT\", ""); // 상위 루트 제거
            }

            else if (regPath.Contains("HKEY_CURRENT_USER"))
            {
                rk = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser,
                                              Environment.Is64BitOperatingSystem
                                                  ? RegistryView.Registry64
                                                  : RegistryView.Registry32);
                regPath = regPath.Replace(@"HKEY_CURRENT_USER\", ""); // 상위 루트 제거
            }

            else if (regPath.Contains("HKEY_LOCAL_MACHINE"))
            {
                rk = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
                                             Environment.Is64BitOperatingSystem
                                                 ? RegistryView.Registry64
                                                 : RegistryView.Registry32);
                regPath = regPath.Replace(@"HKEY_LOCAL_MACHINE\", ""); // 상위 루트 제거
            }
            rk.Close();
            return rk;
        }

        internal static bool Exist(string regPath, in string regName)
        {
            bool result = false;
            string regPathTemp = regPath; // Temp 쓴 이유 : 이것을 2번쓰는 함수의 경우 RegPathKeyCreate 시 regPath 앞에 루트위치가 지워져서 temp를 통해 그것을 방지
            RegistryKey rk = RegPathCreate(ref regPathTemp);

            try
            {
                if (rk != null)
                {
                    if (rk.OpenSubKey(regPathTemp, true).GetValue(regName) != null) // null이면 값이 없음 null이 아니면 값이 있음
                        result = true;
                }
            }
            catch { };

            rk.Close();
            return result;
        }

        internal static bool Write(string regPath, in string regName, in string regValue, in RegValueKind regType)
        {
            bool result = false;
            RegistryKey rk = RegPathCreate(ref regPath);

            try
            {
                if (rk != null)
                    rk.CreateSubKey(regPath, true).SetValue(regName, regValue, (RegistryValueKind)regType); // regPath에 적힌 키를 생성후 그 안에 Value를 생성한다.
                result = true; // 생성도중 문제가 발생하지 않았다면 TRUE
            }
            catch { };

            rk.Close();
            return result;
        }

        internal static bool Delete(string regPath, in string regName)
        {
            bool result = false;
            if (!Exist(regPath, regName)) //레지 path에 regName이 없다면 true
                return true;

            RegistryKey rk = RegPathCreate(ref regPath);

            try
            {
                if (rk != null)
                {
                    rk.OpenSubKey(regPath, true).DeleteValue(regName); // 객체에 대해 레지값을 열고 regName에 해당하는 벨류를 제거하라.
                    result = true; // 제거하는 도중 문제가 생기지 않았다면 true
                }
            }
            catch { };

            rk.Close();
            return result;
        }


        internal static string GetNameValue(string regPath, in string regName)
        {
            object getValue = null;
            RegistryKey rk = RegPathCreate(ref regPath);

            try
            {
                if (rk != null)
                    getValue = rk.CreateSubKey(regPath, true).GetValue(regName);
            }
            catch { };

            rk.Close();
            return getValue.ToString();
        }

        internal static bool SetOwnerPermission(in string AccountName, string RegPath)
        {
            bool result = false;
            if (Privilege.Set(PRIVILEGESLIST.SeTakeOwnershipPrivilege, true))
            {
                NTAccount ntAccount = new NTAccount(AccountName);
                string sSid = ntAccount.Translate(typeof(SecurityIdentifier)).Value;

                IntPtr pSid = IntPtr.Zero;
                ConvertStringSidToSid(sSid, out pSid);
                IntPtr hKey = IntPtr.Zero;

                IntPtr RegRootKey = IntPtr.Zero;
                if (RegPath.Contains("HKEY_CLASSES_ROOT"))
                {
                    RegRootKey = (IntPtr)RegRootKeyKind.HKEY_CLASSES_ROOT;
                    RegPath = RegPath.Replace(@"HKEY_CLASSES_ROOT\", "");
                }
                else if (RegPath.Contains("HKEY_CURRENT_USER"))
                {
                    RegRootKey = (IntPtr)RegRootKeyKind.HKEY_CURRENT_USER;
                    RegPath = RegPath.Replace(@"HKEY_CURRENT_USER\", "");
                }
                else if (RegPath.Contains("HKEY_LOCAL_MACHINE"))
                {
                    RegRootKey = (IntPtr)RegRootKeyKind.HKEY_LOCAL_MACHINE;
                    RegPath = RegPath.Replace(@"HKEY_LOCAL_MACHINE\", "");
                }

                const int OWNER_SECURITY_INFORMATION = 0x00000001;
                const int WRITE_OWNER = (int)ACCESS_MASK.WRITE_OWNER;
                uint dwErr = RegOpenKeyEx(RegRootKey, RegPath, 0,
                    (Environment.Is64BitOperatingSystem ? (int)RegistryView.Registry64 : (int)RegistryView.Registry32) | WRITE_OWNER, ref hKey);
                if (dwErr == 0)
                {
                    if (SetSecurityInfo(hKey,
                         SE_OBJECT_TYPE.SE_REGISTRY_KEY,
                         OWNER_SECURITY_INFORMATION,
                         pSid,
                         IntPtr.Zero,
                         IntPtr.Zero,
                         IntPtr.Zero) == 0)
                        result = true;
                }
                RegCloseKey(hKey);
            }
            return result;
        }

        internal static bool SetReadOnlyPermission(string RegPath)
        {
            bool result = false;
            //필수요소 권한 얻기
            if (Privilege.Set(PRIVILEGESLIST.SeBackupPrivilege, true) &&
                Privilege.Set(PRIVILEGESLIST.SeRestorePrivilege, true) &&
                Privilege.Set(PRIVILEGESLIST.SeTakeOwnershipPrivilege, true))
            {
                if (RegPath.Contains("HKEY_CLASSES_ROOT"))
                    RegPath = RegPath.Replace("HKEY_CLASSES_ROOT", "ROOT");
                else if (RegPath.Contains("HKEY_CURRENT_USER"))
                    RegPath = RegPath.Replace("HKEY_CURRENT_USER", "CURRENT_USER");
                else if (RegPath.Contains("HKEY_LOCAL_MACHINE"))
                    RegPath = RegPath.Replace("HKEY_LOCAL_MACHINE", "MACHINE");


                int SECURITY_BUILTIN_DOMAIN_RID = 0x00000020;
                int DOMAIN_ALIAS_RID_ADMINS = 0x00000220;

                const int worldAuthority = 1;
                const int ntAuthority = 5;
                SidIdentifierAuthority sid_auth_world = new SidIdentifierAuthority();
                sid_auth_world.Value = new byte[] { 0, 0, 0, 0, 0, worldAuthority };
                SidIdentifierAuthority sid_auth_nt = new SidIdentifierAuthority();
                sid_auth_nt.Value = new byte[] { 0, 0, 0, 0, 0, ntAuthority };

                //어드미니스트레이터 값 가져와
                IntPtr sid_Everyone = IntPtr.Zero;
                IntPtr sid_System = IntPtr.Zero;
                IntPtr sid_Admin = IntPtr.Zero;
                IntPtr sid_User = IntPtr.Zero;


                AllocateAndInitializeSid(ref sid_auth_world, 1, 0x0, 0, 0, 0, 0, 0, 0, 0, out sid_Everyone);
                AllocateAndInitializeSid(ref sid_auth_nt, 1, 0x12, 0, 0, 0, 0, 0, 0, 0, out sid_System);
                AllocateAndInitializeSid(ref sid_auth_nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, out sid_Admin);
                AllocateAndInitializeSid(ref sid_auth_nt, 2, 0x20, 0x221, 0, 0, 0, 0, 0, 0, out sid_User);

                IntPtr[] sidList = { sid_Everyone, sid_System, sid_Admin, sid_User };
                //1. EveryOne,System,Admin,User Sid ReadOnly Create
                EXPLICIT_ACCESS[] explicitAccesss = new EXPLICIT_ACCESS[4];
                for (int i = 0; i < sidList.Length; i++)
                {
                    explicitAccesss[i].grfAccessPermissions = (uint)ACCESS_MASK.GENERIC_READ;
                    explicitAccesss[i].grfAccessMode = (uint)ACCESS_MODE.SET_ACCESS;
                    explicitAccesss[i].grfInheritance = 3;
                    explicitAccesss[i].Trustee.TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID;
                    explicitAccesss[i].Trustee.TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_WELL_KNOWN_GROUP;
                    explicitAccesss[i].Trustee.ptstrName = sidList[i];
                }

                //1-1. 완성본으로 만들기
                IntPtr acl_main = Marshal.AllocHGlobal(8);
                SetEntriesInAcl(4, explicitAccesss, IntPtr.Zero, out acl_main);


                //2. 기존 권한 제거
                if (SetNamedSecurityInfo(RegPath
                    , SE_OBJECT_TYPE.SE_REGISTRY_KEY
                    , SECURITY_INFORMATION.Dacl
                    , IntPtr.Zero
                    , IntPtr.Zero
                    , IntPtr.Zero
                    , IntPtr.Zero
                    ) == 0)
                {
                    //3. 권한 만든거 추가
                    if (SetNamedSecurityInfo(RegPath
                    , SE_OBJECT_TYPE.SE_REGISTRY_KEY
                    , SECURITY_INFORMATION.Dacl | SECURITY_INFORMATION.Owner
                    , sid_System //레지 총괄 소유자
                    , IntPtr.Zero
                    , acl_main
                    , IntPtr.Zero) == 0)
                        result = true;
                }


                foreach (IntPtr sid in sidList)
                    FreeSid(sid);
                Marshal.FreeHGlobal(acl_main);
            }
            return result;
        }

        internal static bool SetRestorePermission(string RegPath)
        {
            bool result = false;

            if (Privilege.Set(PRIVILEGESLIST.SeBackupPrivilege, true) &&
            Privilege.Set(PRIVILEGESLIST.SeRestorePrivilege, true) &&
            Privilege.Set(PRIVILEGESLIST.SeTakeOwnershipPrivilege, true))
            {
                if (RegPath.Contains("HKEY_CLASSES_ROOT"))
                    RegPath = RegPath.Replace("HKEY_CLASSES_ROOT", "ROOT");
                else if (RegPath.Contains("HKEY_CURRENT_USER"))
                    RegPath = RegPath.Replace("HKEY_CURRENT_USER", "CURRENT_USER");
                else if (RegPath.Contains("HKEY_LOCAL_MACHINE"))
                    RegPath = RegPath.Replace("HKEY_LOCAL_MACHINE", "MACHINE");

                IntPtr sidOwner, sidGroup, dacl, sacl, daclDescriptor = IntPtr.Zero;

                if (GetNamedSecurityInfo( RegPath + @"\Parameters"
                    , SE_OBJECT_TYPE.SE_REGISTRY_KEY
                    , SECURITY_INFORMATION.Dacl | SECURITY_INFORMATION.UnprotectedDacl | SECURITY_INFORMATION.Owner
                    , out sidOwner
                    , out sidGroup
                    , out dacl//acl_main
                    , out sacl
                    , out daclDescriptor) == 0)
                {
                    if (SetNamedSecurityInfo(RegPath
                    , SE_OBJECT_TYPE.SE_REGISTRY_KEY
                    , SECURITY_INFORMATION.Dacl | SECURITY_INFORMATION.UnprotectedDacl | SECURITY_INFORMATION.Owner
                    , sidOwner //레지 총괄 소유자
                    , sidGroup
                    , dacl//acl_main
                    , sacl) == 0)
                        result = true;
                }
            }
            return result;
        }
    }
    #endregion

    #region File
    public class File
    {
        public static bool Exist(in string filePath, in string fileName)
        {
            try
            {
                if (System.IO.File.Exists(filePath + @"\" + fileName)) // 파일이 있는지 확인한다
                    return true; // 있다면 true
            }
            catch { };

            return false;
        }

        public static bool Copy(in string sourceFilePath, in string destmationFilePath)
        {
            try
            {
                System.IO.File.Copy(sourceFilePath, destmationFilePath); // 파일을 복사한다.
                return true; // 문제없이 잘 됐다면 성공
            }
            catch { };

            return false;
        }

        public static bool Delete(in string filePath, in string fileName)
        {
            try
            {
                if (!Exist(filePath, fileName)) //파일이 없을 경우
                    return true;

                System.IO.File.Delete(filePath + @"\" + fileName); // 파일을 제거한다.
                return true; // 문제없이 잘 됐다면 true
            }
            catch { };

            return false;
        }
    }
    #endregion

    #region Service

    public class Service
    {
        public static bool ConfigChange(in string serviceName, in ServiceStartupType serviceStartupType)
        {
            bool result = false;
            IntPtr scmHandle = OpenSCManager(null, null, SCM_ACCESS.GENERIC_ALL);

            if (scmHandle != IntPtr.Zero)
            {
                IntPtr serviceHandle = OpenService(scmHandle, serviceName, SERVICE_ACCESS.SERVICE_QUERY_CONFIG | SERVICE_ACCESS.SERVICE_CHANGE_CONFIG);

                if (serviceHandle != IntPtr.Zero)
                {
                    result = ChangeServiceConfig(serviceHandle, SERVICE_ACCESS.SERVICE_NO_CHANGE, serviceStartupType,
                        SERVICE_ACCESS.SERVICE_NO_CHANGE, null, null, IntPtr.Zero, null, null, null, null);
                }
                CloseServiceHandle(serviceHandle);
            }
            CloseServiceHandle(scmHandle);

            return result;
        }

        public static bool StatusChange(in string serviceName, in SERVICE_ACCESS serviceStatus)
        {
            bool result = false;
            IntPtr SCMHandle = OpenSCManager(null, null, SCM_ACCESS.GENERIC_ALL);
            if (SCMHandle != IntPtr.Zero)
            {
                IntPtr schService = OpenService(SCMHandle, serviceName, serviceStatus);// SERVICE_ACCESS.SERVICE_QUERY_STATUS | SERVICE_ACCESS.SERVICE_ENUMERATE_DEPENDENTS
                if (schService != IntPtr.Zero)
                {
                    SERVICE_STATUS ssp = new SERVICE_STATUS();
                    bool bResult = ControlService(schService, SERVICE_CONTROL.STOP, ref ssp);
                    if (bResult)
                        result = true;
                }
                CloseServiceHandle(schService);
            }
            CloseServiceHandle(SCMHandle);
            return result;
        }

        public static ServiceController[] GetServiceList()
        {
            return ServiceController.GetServices();
            //foreach (ServiceController service in services)
            //    MessageBox

            ///<summary>
            /// ServiceName = 실질적인 서비스 이름
            /// DisplayName = 표시되는 서비스 이름
            /// </summary>

        }
    }
    #endregion

    #region Dos
    public class Dos
    {
        public static int Cmd(in string Command)
        {
            int result = -999;
            using (Process ps = new Process())
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = @"cmd.exe";
                psi.WorkingDirectory = @"%windir%\system32";
                psi.CreateNoWindow = false;

                psi.UseShellExecute = true; //true = Process클래스가 ShellExecute 함수 사용. False로하면 CreateProcess로 사용. WorkingDirectory를 쓰려면 True로 해야됨.
                psi.RedirectStandardInput = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                ps.EnableRaisingEvents = false;
                ps.StartInfo = psi;
                ps.Start();
                ps.StandardInput.WriteLine(Command);
                ps.StandardInput.Close();
                ps.WaitForExit();
                return result = ps.ExitCode;
            }
        }

        private static string CommandCreate(string Execute, string Commands, string Value)
        {
            StringBuilder Command = new StringBuilder(Execute + " ");
            Command.Append(Commands).Append(" ").Append(Value);

            return Command.ToString();
        }

        public static string Ps(in string Argument)
        {
            using (Process ps = new Process())
            {
                ps.StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = Argument,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true // 창 표시 
                };
                ps.Start();
                return ps.StandardOutput.ReadToEnd();
            };
        }
    }
    #endregion

    #region Privilege

    public class Privilege
    {
        public static bool Set(in string privilege, bool setApply)
        {
            setApply = (setApply == true) ? setApply = false : setApply = true; //false가 활성화 시키는 것임

            bool result = false;

            //현재 프로세스에 대한 핸들 얻어옴
            IntPtr hProcess = GetCurrentProcess();

            //현재 프로세스에 대한 액세스 토큰 오픈(핸들값 획득)
            IntPtr hToken;
            if (OpenProcessToken(hProcess, TokenDesiredAccess.TOKEN_QUERY | TokenDesiredAccess.TOKEN_ADJUST_PRIVILEGES, out hToken) != false)
            {
                //명시된 권한을 표현할 LUID 검색 (LUID : 특정 권한을 표현하는 구조체)
                LUID luid = new LUID();
                if (LookupPrivilegeValue(null, privilege, out luid) != false)
                {

                    // First, a LUID_AND_ATTRIBUTES structure that points to Enable a privilege.
                    LUID_AND_ATTRIBUTES luAttr = new LUID_AND_ATTRIBUTES
                    {
                        Luid = luid,
                        Attributes = LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED
                    };

                    // Now we create a TOKEN_PRIVILEGES structure with our modifications
                    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                    {
                        PrivilegeCount = 1,
                        Privileges = new LUID_AND_ATTRIBUTES[1]
                    };
                    tp.Privileges[0] = luAttr;
                    TOKEN_PRIVILEGES oldState = new TOKEN_PRIVILEGES(); // Our old state.

                    //권한 조정
                    result = AdjustTokenPrivileges(hToken, setApply, ref tp, (UInt32)Marshal.SizeOf(tp), ref oldState, out UInt32 returnLength);
                }
                CloseHandle(hProcess);
                CloseHandle(hToken);
            }
            return result;
        }


        public static bool SetImpersonate(in string processName)
        {
            bool result = false;

            Process[] processlist = Process.GetProcesses();
            IntPtr tokenHandle = IntPtr.Zero;            
            foreach (Process theProcess in processlist)
            {
                if (theProcess.ProcessName == processName)
                {
                    bool token = OpenProcessToken(theProcess.Handle, TokenDesiredAccess.TOKEN_READ | TokenDesiredAccess.TOKEN_IMPERSONATE | TokenDesiredAccess.TOKEN_DUPLICATE, out tokenHandle);
                    if (token)
                        result = ImpersonateLoggedOnUser(tokenHandle);
                    CloseHandle(theProcess.Handle);
                    break;
                }
            }
            return result;
        }


        public static bool SetTrustedInstaller()
        {
            bool result = false;
            if (SetImpersonate("winlogon")) // 권한을 얻어와야지만 TrustedInstaller를 쓸 수 있음.
            {
                IntPtr SCMHandle = OpenSCManager(null, null, SCM_ACCESS.GENERIC_ALL);
                if (SCMHandle != IntPtr.Zero)
                {
                    const string ServiceName = "TrustedInstaller";
                    IntPtr schService = OpenService(SCMHandle, ServiceName, SERVICE_ACCESS.SERVICE_START);

                    if (StartService(schService, 0, null))
                        result = SetImpersonate("TrustedInstaller");
                }
                CloseServiceHandle(SCMHandle);
            }
            return result;
        }
    }

    #endregion

    #region Log
    public class Log
    {
        private static string currentFileName;

        internal static bool WriteCreateLogFile()
        {
            string folderPath = Directory.GetCurrentDirectory() + @"\Log\";
            string filePath = folderPath + Time.GetCurrentTimeStr() + ".log";

            try
            {
                DirectoryInfo DI = new DirectoryInfo(folderPath);
                FileInfo FI = new FileInfo(filePath);

                if (DI.Exists == false)
                    Directory.CreateDirectory(folderPath);
                if (FI.Exists == false)
                {
                    using (StreamWriter SW = new StreamWriter(filePath, true, Encoding.Default))
                    {
                        //StreamWriter = 프로그램 데이터를 텍스트파일로 보낼때 || StreamReader = 텍스트파일을 프로그램상으로 불러올때 || FileStream으로 파일 경로,옵션,접근타입의 옵션을 설정하는 클래스
                        currentFileName = filePath;
                        SW.Write("");
                        SW.Close();
                    }
                }
            }
            catch { };

            return true;
        }

        internal static void WriteLogFile(in string msg)
        {
            try
            {
                FileInfo FI = new FileInfo(currentFileName);
                if (FI.Exists == false)
                    return;

            }
            catch { };

            using (StreamWriter SW = new StreamWriter(currentFileName, true, Encoding.Default))
            {
                SW.WriteLine(Time.GetCurrentTimeStr() + ": " + msg);
                SW.Close();
            }
        }
    }
    #endregion
}