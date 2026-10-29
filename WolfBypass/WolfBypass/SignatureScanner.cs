using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;

namespace WolfBypass
{
    public class ModuleInfo
    {
        public IntPtr BaseAddress;
        public int ModuleMemorySize;
        public string ModuleName;
    }

    public class SignatureScanner
    {
        public string Tag = "";
        public Process Proc;

        const int CHUNK = 0x400000;
        const uint MEM_COMMIT = 0x1000, MEM_IMAGE = 0x1000000, MEM_MAPPED = 0x40000;
        const uint PAGE_NOACCESS = 0x01, PAGE_GUARD = 0x100;

        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool b, uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
        [DllImport("ntdll.dll")] static extern int NtReadVirtualMemory(IntPtr h, IntPtr a, byte[] b, UIntPtr s, out UIntPtr r);
        [DllImport("ntdll.dll")] static extern int NtQueryVirtualMemory(IntPtr h, IntPtr a, int cls, out MEMORY_BASIC_INFORMATION m, UIntPtr len, out UIntPtr ret);

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress, AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State, Protect, Type;
        }

        // Form1'in baglandigi pid'e dogrudan baglan (isimle yeniden arama yok).
        public bool Attach(int pid)
        {
            try { Proc = Process.GetProcessById(pid); return true; }
            catch { return false; }
        }

        public bool GetProcess(string name)
        {
            try
            {
                var list = Process.GetProcessesByName(name);
                if (list.Length == 0) list = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(name));
                if (list.Length == 0) return false;
                Proc = list[0];
                return true;
            }
            catch { return false; }
        }

        public ModuleInfo GetModule(string pattern)
        {
            if (Proc == null) return null;
            var rx = new Regex(pattern, RegexOptions.IgnoreCase);

            // 1) PEB modul listesi
            try
            {
                Proc.Refresh();
                foreach (ProcessModule m in Proc.Modules)
                    if (rx.IsMatch(m.ModuleName))
                        return new ModuleInfo { BaseAddress = m.BaseAddress, ModuleMemorySize = m.ModuleMemorySize, ModuleName = m.ModuleName };
            }
            catch { }

            // 2) VAD walk — PEB'de gorunmeyen / manuel map'li modul icin
            IntPtr h = OpenProcess(0x410, false, (uint)Proc.Id);
            if (h == IntPtr.Zero) return null;
            try
            {
                IntPtr addr = (IntPtr)0x10000; MEMORY_BASIC_INFORMATION mbi; UIntPtr outLen;
                var sz = (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                while (addr.ToInt64() < 0x7FFFFFFF)
                {
                    if (NtQueryVirtualMemory(h, addr, 0, out mbi, sz, out outLen) != 0) break;
                    long rs = (long)mbi.RegionSize.ToUInt64(); if (rs <= 0) break;
                    if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED))
                    {
                        var nm = ReadImageName(h, mbi.BaseAddress);
                        if (!string.IsNullOrEmpty(nm) && rx.IsMatch(nm))
                            return new ModuleInfo { BaseAddress = mbi.BaseAddress, ModuleMemorySize = (int)Math.Min(rs, int.MaxValue), ModuleName = nm };
                    }
                    addr = (IntPtr)(mbi.BaseAddress.ToInt64() + rs);
                }
            }
            finally { CloseHandle(h); }
            return null;
        }

        static void ParseSig(string sigStr, string maskStr, out byte[] pat, out bool[] mask)
        {
            var parts = sigStr.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            pat = new byte[parts.Length];
            mask = new bool[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                bool wild = parts[i] == "?" || parts[i] == "??";
                if (!wild && maskStr != null && i < maskStr.Length && maskStr[i] != 'x') wild = true;
                mask[i] = wild;
                pat[i] = wild ? (byte)0 : Convert.ToByte(parts[i], 16);
            }
        }

        // Bolge-farkinda tarama: unmapped/guard sayfalar atlanir, okuma bolge sinirinda kesilir.
        public List<IntPtr> FindAll(IntPtr start, IntPtr end, byte[] pat, bool[] mask, int cap)
        {
            var res = new List<IntPtr>();
            if (Proc == null || pat == null || pat.Length == 0) return res;
            IntPtr h = OpenProcess(0x438, false, (uint)Proc.Id);
            if (h == IntPtr.Zero) return res;
            try
            {
                var buf = new byte[CHUNK + 64];
                long a = start.ToInt64(), e = end.ToInt64();
                MEMORY_BASIC_INFORMATION mbi; UIntPtr outLen;
                var sz = (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                while (a < e && res.Count < cap)
                {
                    long regionEnd = e;
                    if (NtQueryVirtualMemory(h, (IntPtr)a, 0, out mbi, sz, out outLen) == 0)
                    {
                        long rs = (long)mbi.RegionSize.ToUInt64();
                        if (rs > 0) regionEnd = Math.Min(e, mbi.BaseAddress.ToInt64() + rs);
                        bool readable = mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_NOACCESS) == 0 && (mbi.Protect & PAGE_GUARD) == 0;
                        if (!readable) { a = regionEnd > a ? regionEnd : a + 0x1000; continue; }
                    }
                    long take = Math.Min(CHUNK, regionEnd - a);
                    if (take <= 0) { a += 0x1000; continue; }
                    long readLen = Math.Min(take + pat.Length - 1, regionEnd - a);
                    UIntPtr n;
                    if (NtReadVirtualMemory(h, (IntPtr)a, buf, (UIntPtr)readLen, out n) != 0) { a += take; continue; }
                    long max = readLen - pat.Length;
                    for (long i = 0; i <= max && i < take; i++)
                    {
                        bool ok = true;
                        for (int j = 0; j < pat.Length; j++) if (!mask[j] && buf[i + j] != pat[j]) { ok = false; break; }
                        if (ok) { res.Add((IntPtr)(a + i)); if (res.Count >= cap) break; }
                    }
                    a += take;
                }
            }
            finally { CloseHandle(h); }
            return res;
        }

        public IntPtr Find(IntPtr start, IntPtr end, string sigStr, string maskStr)
        {
            byte[] pat; bool[] mask;
            ParseSig(sigStr, maskStr, out pat, out mask);
            var hits = FindAll(start, end, pat, mask, 1);
            return hits.Count > 0 ? hits[0] : IntPtr.Zero;
        }

        public T Read<T>(IntPtr addr) where T : struct
        {
            if (Proc == null) return default(T);
            IntPtr h = OpenProcess(0x410, false, (uint)Proc.Id);
            if (h == IntPtr.Zero) return default(T);
            try
            {
                int size = Marshal.SizeOf(typeof(T));
                var buf = new byte[size]; UIntPtr n;
                if (NtReadVirtualMemory(h, addr, buf, (UIntPtr)size, out n) != 0) return default(T);
                var gc = GCHandle.Alloc(buf, GCHandleType.Pinned);
                try { return (T)Marshal.PtrToStructure(gc.AddrOfPinnedObject(), typeof(T)); }
                finally { gc.Free(); }
            }
            finally { CloseHandle(h); }
        }

        string ReadImageName(IntPtr h, IntPtr baseAddr)
        {
            try
            {
                var mz = new byte[2]; UIntPtr n;
                if (NtReadVirtualMemory(h, baseAddr, mz, (UIntPtr)2, out n) != 0 || mz[0] != 0x4D || mz[1] != 0x5A) return null;
                var e4 = new byte[4];
                if (NtReadVirtualMemory(h, IntPtr.Add(baseAddr, 0x3C), e4, (UIntPtr)4, out n) != 0) return null;
                int e = BitConverter.ToInt32(e4, 0);
                if (e <= 0 || e > 0x1000) return null;
                IntPtr pe = IntPtr.Add(baseAddr, e);
                var sig = new byte[4];
                if (NtReadVirtualMemory(h, pe, sig, (UIntPtr)4, out n) != 0 || sig[0] != 0x50 || sig[1] != 0x45) return null;
                var magic = new byte[2];
                if (NtReadVirtualMemory(h, IntPtr.Add(pe, 24), magic, (UIntPtr)2, out n) != 0) return null;
                int ddOff = BitConverter.ToInt16(magic, 0) == 0x10B ? 96 : 112;
                var exp = new byte[4];
                if (NtReadVirtualMemory(h, IntPtr.Add(pe, 24 + ddOff), exp, (UIntPtr)4, out n) != 0) return null;
                int expRva = BitConverter.ToInt32(exp, 0);
                if (expRva <= 0) return null;
                var nm = new byte[4];
                if (NtReadVirtualMemory(h, IntPtr.Add(baseAddr, expRva + 12), nm, (UIntPtr)4, out n) != 0) return null;
                int nameRva = BitConverter.ToInt32(nm, 0);
                if (nameRva <= 0) return null;
                var sb = new byte[64];
                if (NtReadVirtualMemory(h, IntPtr.Add(baseAddr, nameRva), sb, (UIntPtr)64, out n) != 0) return null;
                var s = Encoding.ASCII.GetString(sb); int z = s.IndexOf('\0'); return z >= 0 ? s.Substring(0, z) : s;
            }
            catch { return null; }
        }

        public void Close() { Proc = null; }
    }
}