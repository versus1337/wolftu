using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Net;
using System.IO;
using Timer = System.Windows.Forms.Timer;

namespace WolfBypass
{
    public class Form1 : Form
    {
        // ================= Win32 / NT =================
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool b, uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, UIntPtr s, uint t, uint p);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool VirtualFreeEx(IntPtr h, IntPtr a, UIntPtr s, uint t);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool VirtualProtectEx(IntPtr h, IntPtr a, UIntPtr s, uint np, out uint op);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr ph, uint da, out IntPtr th);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool LookupPrivilegeValue(string a, string b, out LUID l);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr th, bool dis, ref TOKEN_PRIVILEGES np, uint bl, IntPtr pp, out uint rl);

        [DllImport("ntdll.dll")] static extern int NtReadVirtualMemory(IntPtr h, IntPtr a, byte[] b, UIntPtr s, out UIntPtr r);
        [DllImport("ntdll.dll")] static extern int NtWriteVirtualMemory(IntPtr h, IntPtr a, byte[] b, UIntPtr s, out UIntPtr r);
        [DllImport("ntdll.dll")] static extern int NtProtectVirtualMemory(IntPtr h, ref IntPtr a, ref UIntPtr s, uint np, out uint op);
        [DllImport("ntdll.dll")] static extern int NtQueryVirtualMemory(IntPtr h, IntPtr a, int cls, out MEMORY_BASIC_INFORMATION m, UIntPtr len, out UIntPtr ret);

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress, AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State, Protect, Type;
        }
        [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
        [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

        const uint PROCESS_VM_OPERATION = 0x8, PROCESS_VM_READ = 0x10, PROCESS_VM_WRITE = 0x20, PROCESS_QUERY_INFORMATION = 0x400;
        const uint ACCESS_NEEDED = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
        const uint PAGE_EXECUTE_READWRITE = 0x40, MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_RELEASE = 0x8000, MEM_IMAGE = 0x1000000, MEM_MAPPED = 0x40000;
        const int SCAN_CHUNK = 0x400000;

        // ================= Yama modeli =================
        class Patch
        {
            public string Name, ModKey; public int Offset; public byte[] Bytes; public CheckBox Chk;
            public byte[] Original; public IntPtr OriginalBase; public int CapLen;
            public byte[] Sig; public bool[] SigMask; public bool Verified;
            public bool WriteFailed, Relocated, Warned;
            public string SigStr;          // bu yamaya ait imza metni (ayri tanimlayici)
            public SignatureScanner Sc;    // bu yamaya ait AYRI tarayici
            public int DefOffset;          // koddaki fabrika offseti
            public byte Orig;              // 1-baytlik yamalarda BEKLENEN orijinal bayt (0 = kontrol yok)
        }
        readonly List<Patch> patches = new List<Patch>();
        Patch pNoSpread, pRapidFire;
        const float JUMP_VALUE = 1.5f, SPEED_VALUE = 1.0f;

        class CapHook { public IntPtr Slot; }
        readonly List<CapHook> capHooks = new List<CapHook>();
        class ActiveHook { public IntPtr Target; public byte[] Orig5; public IntPtr Cave; }
        readonly List<ActiveHook> activeHooks = new List<ActiveHook>();

        Process target; int pid;
        IntPtr hookAddr = IntPtr.Zero; int hookIdx = 0;
        bool armed = false;

        readonly List<string> candidates = new List<string> {
            "FAC2BCCBFB7B2C40CA3955155BDD873B",
            "2726E7BC72392CCE5203AA258ADC18E9",
            "B0E2B4CC6326C8D69BB4913FFDAEAACC" };

        // =====================================================================
        //  IMZA TANIMLAYICILARI  (her imza icin AYRI degisken)
        //  Bos ("") olanlar 'Imza Uret' ile TEK olacak sekilde uretilir.
        //  Kural: emin degilsen elle yazma, bos birak -> urettir.
        // =====================================================================
        // --- obj ---
        readonly string sigRestoreHP        = "?? 45 ?? d9 5d ?? d9 45 ?? dc 1d ?? ?? ?? ?? df e0 f6 c4 ?? 7b";  // obj+50318 (FLD -> FADD)
        readonly string sigAlwaysHeadShot   = "?? 45 ?? d9 5d ?? d9 45 ?? dc 1d ?? ?? ?? ?? df e0 f6 c4 ?? 7b";  // obj+46003C (FLD -> FADD)
        readonly string sigGodMode          = "";                              // obj+1EF6D
        readonly string sigRemoteKill       = "";                              // obj+E3109
        readonly string sigHpBooster        = "";                              // obj+5C89F
        readonly string sigAllFreezePlayer  = "";                              // obj+3D637
        readonly string sigPowerfulBomb     = "";                              // obj+139437
        readonly string sigBombNoBounce     = "";                              // obj+139421
        readonly string sigAimbotUltra      = "74 28 15 68 8D 58";             // obj+1C92A
        // --- csh ---
        readonly string sigNoRecoil         = "?? ?? ?? ?? 00 00 34";          // csh+45A37C
        readonly string sigRapidFire        = "";                              // csh+1218DA  (otomatik uret)
        readonly string sigJumpHack         = "29 5C 4F 3F 00 50";             // csh+4628E4
        readonly string sigInfAmmo          = "74 0E 83 F8 02 74 09 83 F8 05"; // csh+676AD
        readonly string sigNoReload         = "?? 06 8B 86 6C 01";             // csh+1565EA
        readonly string sigNoFallDamage     = "EE C7 00 54 03 46";             // csh+F9D53
        readonly string sigWolfDashSpeed    = "";                              // csh+E5876
        readonly string sigInfWolf          = "8A 45 08 88 86 E5";             // csh+BFB4C
        readonly string sigAntiChatBan      = "80 B9 18 D2 03 00 00 0F";       // csh+168390
        readonly string sigInstantRespawn   = "34 46 EB 06 8B 35";             // csh+A2060
        readonly string sigRespawnWhereDied = "68 4B 72 3F 34 64";             // csh+F7D75
        readonly string sigNoWeaponSp       = "75 12 0F B7 45 08";             // csh+1E8E80
        readonly string sigMovementSpeed    = "74 34 8D 8E 30 02 00 00 E8";    // csh+1ABC31
        readonly string sigSpeedHackEnable  = "75 0C D9 05 50 70";             // csh+12461
        readonly string sigSpeedHackValue   = "CD CC CC 3D 00 00 00 00 00";    // csh+4373E8
        readonly string sigNoSpread         = "";                              // csh+123834  (otomatik uret)

         readonly string SignameESP = "74 ?? ?? ?? ?? ?? ?? 8B";  // Örnek pattern, senin bulduğun byte'ların etrafından
        // --- wolf ---
        readonly string sigWallShot1        = "15 C8 29 72 00 C7 40 4C";       // wolf+4F171
        readonly string sigWallShot2        = "F6 C4 41 75 15 D8 D5";          // wolf+67533
        readonly string sigWallShot3        = "D8 4E 08 D9 46 04 D8 0E";       // wolf+59F8B
        readonly string sigWallShot4        = "85 1C FF FF FF D9 5D F8";       // wolf+5A131
        readonly string sigNoClip           = "00 FF D6 68 CC 62";             // wolf+85F21
        // --- msvcr ---
        readonly string sigSwearHack        = "74 3F 8B D1 2B C3";             // msvcr+1339B

        // --- HER IMZA ICIN AYRI TARAYICI ORNEGI ---
        readonly SignatureScanner scRestoreHP        = new SignatureScanner { Tag = "Restore HP" };
        readonly SignatureScanner scAlwaysHeadShot   = new SignatureScanner { Tag = "Always HeadShot" };
        readonly SignatureScanner scGodMode          = new SignatureScanner { Tag = "God Mode" };
        readonly SignatureScanner scRemoteKill       = new SignatureScanner { Tag = "Remote Kill" };
        readonly SignatureScanner scHpBooster        = new SignatureScanner { Tag = "HP Booster" };
        readonly SignatureScanner scAllFreezePlayer  = new SignatureScanner { Tag = "All Freeze Player" };
        readonly SignatureScanner scPowerfulBomb     = new SignatureScanner { Tag = "Powerful Bomb" };
        readonly SignatureScanner scBombNoBounce     = new SignatureScanner { Tag = "Bomb No Bounce" };
        readonly SignatureScanner scAimbotUltra      = new SignatureScanner { Tag = "Aimbot Ultra" };
        readonly SignatureScanner scNoRecoil         = new SignatureScanner { Tag = "No Recoil" };
        readonly SignatureScanner scRapidFire        = new SignatureScanner { Tag = "Rapid Fire" };
        readonly SignatureScanner scJumpHack         = new SignatureScanner { Tag = "Jump Hack" };
        readonly SignatureScanner scInfAmmo          = new SignatureScanner { Tag = "Infinite Ammo" };
        readonly SignatureScanner scNoReload         = new SignatureScanner { Tag = "No Reload" };
        readonly SignatureScanner scNoFallDamage     = new SignatureScanner { Tag = "No Fall Damage" };
        readonly SignatureScanner scWolfDashSpeed    = new SignatureScanner { Tag = "Wolf Dash Speed" };
        readonly SignatureScanner scInfWolf          = new SignatureScanner { Tag = "Infinite Wolf Balls" };
        readonly SignatureScanner scAntiChatBan      = new SignatureScanner { Tag = "Anti Chat Ban" };
        readonly SignatureScanner scInstantRespawn   = new SignatureScanner { Tag = "Instant Respawn" };
        readonly SignatureScanner scRespawnWhereDied = new SignatureScanner { Tag = "Respawn Where Died" };
        readonly SignatureScanner scNoWeaponSp       = new SignatureScanner { Tag = "No Weapon Sp" };
        readonly SignatureScanner scMovementSpeed    = new SignatureScanner { Tag = "Movement Speed" };
        readonly SignatureScanner scSpeedHackEnable  = new SignatureScanner { Tag = "Speed Hack Enable" };
        readonly SignatureScanner scNameESP  = new SignatureScanner { Tag = "Name ESP" };

        readonly SignatureScanner scSpeedHackValue   = new SignatureScanner { Tag = "Speed Hack Value" };
        readonly SignatureScanner scNoSpread         = new SignatureScanner { Tag = "No Spread" };
        readonly SignatureScanner scWallShot1        = new SignatureScanner { Tag = "WallShot 1" };
        readonly SignatureScanner scWallShot2        = new SignatureScanner { Tag = "WallShot 2" };
        readonly SignatureScanner scWallShot3        = new SignatureScanner { Tag = "WallShot 3" };
        readonly SignatureScanner scWallShot4        = new SignatureScanner { Tag = "WallShot 4" };
        readonly SignatureScanner scNoClip           = new SignatureScanner { Tag = "NoClip" };
        readonly SignatureScanner scSwearHack        = new SignatureScanner { Tag = "Swear Hack" };

        List<IntPtr> scanHits = new List<IntPtr>();
        bool scanIsFloat = false;

        // ================= Modul / imza =================
        readonly Dictionary<string, string> modulePatterns = new Dictionary<string, string> {
            {"obj",  @"^(obj[a-z0-9]*\.tmp|Object\.lto)$"},
            {"csh",  @"^(csh[a-z0-9]*\.tmp|CShell\.dll)$"},
            {"wolf", @"^wolfteam\.bin$"},
            {"msvcr",@"^msvcr100\.dll$"},
            {"d3d9", @"^d3d9\.dll$"} };
        readonly Dictionary<string, IntPtr> bases = new Dictionary<string, IntPtr> {
            {"obj", IntPtr.Zero}, {"csh", IntPtr.Zero}, {"wolf", IntPtr.Zero}, {"msvcr", IntPtr.Zero}, {"d3d9", IntPtr.Zero} };

        readonly string offFile = Path.Combine(Application.StartupPath, "offsets.txt");

        // ================= Kontroller =================
        Button btnConnect = new Button(), btnScanModules = new Button(), btnClean = new Button(), btnDiff = new Button(), btnHook = new Button();
        TextBox txtModules = new TextBox();
        Label lblStatus = new Label();
        Timer TimerHack = new Timer(), TimerModules = new Timer();

        CheckBox chkRestoreHP, chkAlwaysHS, chkGodMode, chkRemoteKill, chkHpBooster, chkAllFreezePlayer,
                 chkPowerfulBomb, chkBombNoBounce, chkAimbotUltra, chkNoRecoil, chkRapidFire, chkJumpHack,
                 chkInfAmmo, chkNoReload, chkNoFallDamage, chkWolfDashSpeed, chkInfWolf, chkAntiChatBan,
                 chkInstantRespawn, chkRespawnWhereDied, chkNoWeaponSp, chkMovementSpeed, chkWallShot, chkNoClip, chkSwearHack,
                 chkNoSpread,chkNameESP, chkReloc;
        ComboBox cmbNsByte, cmbRfByte;

        TextBox txtValue = new TextBox();
        Button btnScan1 = new Button(), btnScan2 = new Button();
        CheckBox chkFloat = new CheckBox();
        TextBox txtPattern = new TextBox(), txtAoBMod = new TextBox();
        Button btnAoB = new Button();
        TextBox txtPtrBase = new TextBox(), txtPtrOffs = new TextBox(), txtRet = new TextBox();
        Button btnPtrRead = new Button();
        Button btnSig = new Button(), btnScanAll = new Button();
        Button btnCapture = new Button(), btnReadCrc = new Button(), btnCapAll = new Button();
        Button btnValidate = new Button(), btnArm = new Button(), btnDump = new Button();
        Button btnOffsetCode = new Button();
        TextBox txtCrc = new TextBox();

        bool RelocEnabled { get { return chkReloc == null || chkReloc.Checked; } }

        // ================= ctor =================
        public Form1()
        {
            Text = "WolfBypass";
            ClientSize = new Size(660, 830);
            try { Icon = new Icon("app.ico"); } catch { }
            try
            {
                using (var wc = new WebClient())
                {
                    byte[] data = wc.DownloadData("https://i.imgur.com/jNsX99X.jpeg");
                    using (var ms = new MemoryStream(data)) BackgroundImage = Image.FromStream(ms);
                }
                BackgroundImageLayout = ImageLayout.Stretch;
            }
            catch { }
            Opacity = 0.95;

            EnableDebugPrivilege();
            BuildControls();
            BuildPatchList();
            LoadOffsets();
            ApplyDefaultSigs();
            ApplyComboBytes();

            TimerHack.Interval = 100;
            TimerModules.Interval = 1500;
            TimerHack.Tick += (s, e) => TimerHack_Tick();
            TimerModules.Tick += (s, e) => TimerModules_Tick();
            FormClosing += (s, e) => { try { RestoreAll(); UnhookAll(); } catch { } Disconnect(); };
        }

        // ================= UI =================
        CheckBox MkChk(string text, ref int i)
        {
            var c = new CheckBox { Text = text, AutoSize = true, Location = new Point(12 + (i / 15) * 210, 12 + (i % 15) * 23) };
            Controls.Add(c); i++; return c;
        }
        ComboBox MkCombo(Point loc, string[] items)
        {
            var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = loc, Size = new Size(125, 22) };
            c.Items.AddRange(items); c.SelectedIndex = 0; Controls.Add(c); return c;
        }
        void Btn(Button b, string t, int x, int y, int w)
        {
            b.Text = t; b.Location = new Point(x, y); b.Size = new Size(w, 26); Controls.Add(b);
        }

        void BuildControls()
        {
            int i = 0;
            chkRestoreHP = MkChk("Restore HP", ref i); chkAlwaysHS = MkChk("Always HeadShot", ref i);
            chkGodMode = MkChk("God Mode", ref i); chkRemoteKill = MkChk("Remote Kill", ref i);
            chkHpBooster = MkChk("HP Booster", ref i); chkAllFreezePlayer = MkChk("All Freeze Player", ref i);
            chkPowerfulBomb = MkChk("Powerful Bomb", ref i); chkBombNoBounce = MkChk("Bomb No Bounce", ref i);
            chkAimbotUltra = MkChk("Aimbot Ultra", ref i); chkNoRecoil = MkChk("No Recoil", ref i);
            chkRapidFire = MkChk("Rapid Fire", ref i); chkJumpHack = MkChk("Jump Hack", ref i);
            chkInfAmmo = MkChk("Infinite Ammo", ref i); chkNoReload = MkChk("No Reload", ref i);
            chkNoFallDamage = MkChk("No Fall Damage", ref i); chkWolfDashSpeed = MkChk("Wolf Dash Speed", ref i);
            chkInfWolf = MkChk("Infinite Wolf Balls", ref i); chkAntiChatBan = MkChk("Anti Chat Ban", ref i);
            chkInstantRespawn = MkChk("Instant Respawn", ref i); chkRespawnWhereDied = MkChk("Respawn Where Died", ref i);
            chkNoWeaponSp = MkChk("No Weapon Sp", ref i); chkMovementSpeed = MkChk("Movement Speed", ref i);
            chkWallShot = MkChk("WallShot", ref i); chkNoClip = MkChk("NoClip", ref i);
            chkSwearHack = MkChk("Swear Hack", ref i);
            chkNoSpread = MkChk("No Spread", ref i);
             chkNameESP = MkChk("Name ESP", ref i);
            chkReloc = MkChk("Offset Tasi (RELOC)", ref i);

            var l1 = new Label { Text = "No Spread bayti:", Location = new Point(12, 364), AutoSize = true }; Controls.Add(l1);
            cmbNsByte = MkCombo(new Point(115, 360), new[] { "74 (JZ)", "90 90 (NOP)", "EB (JMP)", "75 (test)" });
            var l2 = new Label { Text = "Rapid Fire bayti:", Location = new Point(255, 364), AutoSize = true }; Controls.Add(l2);
            cmbRfByte = MkCombo(new Point(355, 360), new[] { "74", "10 (test/no-op)", "75" });
            cmbNsByte.SelectedIndexChanged += (s, e) => ApplyComboBytes();
            cmbRfByte.SelectedIndexChanged += (s, e) => ApplyComboBytes();

            int y = 394;
            Btn(btnConnect, "Baglan", 12, y, 90); btnConnect.Click += (s, e) => BtnConnect_Click();
            Btn(btnScanModules, "Moduller", 106, y, 90); btnScanModules.Click += (s, e) => BtnScanModules_Click();
            Btn(btnClean, "Temizle", 200, y, 80); btnClean.Click += (s, e) => BtnClean_Click();
            Btn(btnDiff, "Diff", 284, y, 70); btnDiff.Click += (s, e) => BtnDiff_Click();
            Btn(btnSig, "Imza Uret", 358, y, 100); btnSig.Click += (s, e) => BtnSig_Click();
            Btn(btnScanAll, "OFSET GUNCELLE (Sig)", 462, y, 150); btnScanAll.Click += (s, e) => UpdateOffsetsFromSigs();
            y += 30;
            Btn(btnValidate, "DOGRULA", 12, y, 100); btnValidate.Click += (s, e) => BtnValidate_Click();
            Btn(btnArm, "PATCH AC", 116, y, 110); btnArm.Click += (s, e) => BtnArm_Click();
            Btn(btnDump, "DUMP", 230, y, 80); btnDump.Click += (s, e) => BtnDump_Click();
            Btn(btnHook, "HOOK", 314, y, 80); btnHook.Click += (s, e) => BtnHook_Click();
            Btn(btnCapture, "CAPTURE", 398, y, 90); btnCapture.Click += (s, e) => BtnCapture_Click();
            Btn(btnReadCrc, "CRC Oku", 492, y, 90); btnReadCrc.Click += (s, e) => BtnReadCrc_Click();
            Btn(btnOffsetCode, "KOD", 586, y, 62); btnOffsetCode.Click += (s, e) => DumpOffsetsCode();
            y += 30;
            txtValue.Location = new Point(12, y); txtValue.Size = new Size(80, 24); txtValue.Text = "100";
            chkFloat.Text = "float"; chkFloat.Location = new Point(98, y + 4); chkFloat.AutoSize = true;
            Btn(btnScan1, "ILK TARAMA", 160, y, 100); btnScan1.Click += (s, e) => BtnScan1_Click();
            Btn(btnScan2, "SONRAKI", 264, y, 90); btnScan2.Click += (s, e) => BtnScan2_Click();
            txtPattern.Location = new Point(360, y); txtPattern.Size = new Size(160, 24); txtPattern.Text = "F6 C4 41 ?? 74";
            txtAoBMod.Location = new Point(526, y); txtAoBMod.Size = new Size(50, 24); txtAoBMod.Text = "csh";
            Btn(btnAoB, "AoB", 580, y, 60); btnAoB.Click += (s, e) => BtnAoB_Click();
            y += 30;
            txtPtrBase.Location = new Point(12, y); txtPtrBase.Size = new Size(90, 24); txtPtrBase.Text = "csh+A2288";
            txtPtrOffs.Location = new Point(106, y); txtPtrOffs.Size = new Size(110, 24); txtPtrOffs.Text = "0x40,0xA50";
            Btn(btnPtrRead, "Pointer Oku", 222, y, 100); btnPtrRead.Click += (s, e) => BtnPtrRead_Click();
            txtRet.Location = new Point(330, y); txtRet.Size = new Size(40, 24); txtRet.Text = "0";
            Btn(btnCapAll, "Tum Call Yakala", 380, y, 150); btnCapAll.Click += (s, e) => BtnCapAll_Click();
            txtCrc.Location = new Point(536, y); txtCrc.Size = new Size(110, 24);
            y += 30;

            Controls.Add(txtValue); Controls.Add(chkFloat); Controls.Add(txtPattern); Controls.Add(txtAoBMod);
            Controls.Add(txtPtrBase); Controls.Add(txtPtrOffs); Controls.Add(txtRet); Controls.Add(txtCrc);

            txtModules.Location = new Point(12, y); txtModules.Size = new Size(636, 830 - y - 34);
            txtModules.Multiline = true; txtModules.ScrollBars = ScrollBars.Vertical; txtModules.ReadOnly = true;
            txtModules.BackColor = Color.FromArgb(20, 20, 20); txtModules.ForeColor = Color.Gainsboro;
            txtModules.Font = new Font("Consolas", 8f);
            Controls.Add(txtModules);

            lblStatus.Location = new Point(12, 830 - 26); lblStatus.AutoSize = true; lblStatus.Text = "Bagli degil";
            Controls.Add(lblStatus);
        }

        // ================= Bayt secimi =================
        byte[] NsBytes()
        {
            switch (cmbNsByte == null ? 0 : cmbNsByte.SelectedIndex)
            {
                case 1: return new byte[] { 0x90, 0x90 };
                case 2: return new byte[] { 0xEB };
                case 3: return new byte[] { 0x75 };
                default: return new byte[] { 0x74 };
            }
        }
        byte[] RfBytes()
        {
            switch (cmbRfByte == null ? 0 : cmbRfByte.SelectedIndex)
            {
                case 1: return new byte[] { 0x10 };
                case 2: return new byte[] { 0x75 };
                default: return new byte[] { 0x74 };
            }
        }
        void ApplyComboBytes()
        {
            if (pNoSpread != null) { pNoSpread.Bytes = NsBytes(); pNoSpread.Verified = false; }
            if (pRapidFire != null) { pRapidFire.Bytes = RfBytes(); pRapidFire.Verified = false; }
        }

        // ================= Yama listesi =================
        void BuildPatchList()
        {
            Action<string, string, int, byte[], CheckBox, string, SignatureScanner> R =
                (n, m, o, b, c, s, sc) => patches.Add(new Patch
                {
                    Name = n, ModKey = m, Offset = o, Bytes = b, Chk = c,
                    SigStr = s, Sc = sc, DefOffset = o
                });

            R("Restore HP", "obj", 0x50318, new byte[] { 0xD8 }, chkRestoreHP, sigRestoreHP, scRestoreHP);
            R("Always HeadShot", "obj", 0x46003C, new byte[] { 0xD8 }, chkAlwaysHS, sigAlwaysHeadShot, scAlwaysHeadShot);
            R("God Mode", "obj", 0x1EF6D, new byte[] { 0xD8 }, chkGodMode, sigGodMode, scGodMode);
            R("Remote Kill", "obj", 0xE3109, new byte[] { 0x74 }, chkRemoteKill, sigRemoteKill, scRemoteKill);
            R("HP Booster", "obj", 0x5C89F, new byte[] { 0x75 }, chkHpBooster, sigHpBooster, scHpBooster);
            R("All Freeze Player", "obj", 0x3D637, new byte[] { 0x74 }, chkAllFreezePlayer, sigAllFreezePlayer, scAllFreezePlayer);
            R("Powerful Bomb", "obj", 0x139437, new byte[] { 0xF6, 0xC4, 0x41, 0x74 }, chkPowerfulBomb, sigPowerfulBomb, scPowerfulBomb);
            R("Bomb No Bounce", "obj", 0x139421, new byte[] { 0xF6, 0xC4, 0x41, 0x74 }, chkBombNoBounce, sigBombNoBounce, scBombNoBounce);
            R("Aimbot Ultra", "obj", 0x1C92A, new byte[] { 0xEB }, chkAimbotUltra, sigAimbotUltra, scAimbotUltra);

            R("No Recoil", "csh", 0x45A37C, BitConverter.GetBytes(0.0f), chkNoRecoil, sigNoRecoil, scNoRecoil);
            R("Rapid Fire", "csh", 0x1218DA, new byte[] { 0x74 }, chkRapidFire, sigRapidFire, scRapidFire);
            R("Jump Hack", "csh", 0x4628E4, BitConverter.GetBytes(JUMP_VALUE), chkJumpHack, sigJumpHack, scJumpHack);
            R("Infinite Ammo", "csh", 0x676AD, new byte[] { 0xEB }, chkInfAmmo, sigInfAmmo, scInfAmmo);
            R("No Reload", "csh", 0x1565EA, new byte[] { 0xEB }, chkNoReload, sigNoReload, scNoReload);
            R("No Fall Damage", "csh", 0xF9D53, new byte[] { 0x74 }, chkNoFallDamage, sigNoFallDamage, scNoFallDamage);
            R("Wolf Dash Speed", "csh", 0xE5876, new byte[] { 0x75 }, chkWolfDashSpeed, sigWolfDashSpeed, scWolfDashSpeed);
            R("Infinite Wolf Balls", "csh", 0xBFB4C, new byte[] { 0xB0, 0x01, 0x90, 0x88 }, chkInfWolf, sigInfWolf, scInfWolf);
            R("Anti Chat Ban", "csh", 0x168390, new byte[] { 0xF6, 0x81, 0x00, 0x00 }, chkAntiChatBan, sigAntiChatBan, scAntiChatBan);
            R("Instant Respawn", "csh", 0xA2060, new byte[] { 0x74 }, chkInstantRespawn, sigInstantRespawn, scInstantRespawn);
            R("Respawn Where Died", "csh", 0xF7D75, new byte[] { 0xEB }, chkRespawnWhereDied, sigRespawnWhereDied, scRespawnWhereDied);
            R("No Weapon Sp", "csh", 0x1E8E80, new byte[] { 0x74 }, chkNoWeaponSp, sigNoWeaponSp, scNoWeaponSp);
            R("Movement Speed", "csh", 0x1ABC31, new byte[] { 0x75 }, chkMovementSpeed, sigMovementSpeed, scMovementSpeed);
            R("Speed Hack Enable", "csh", 0x12461, new byte[] { 0x74 }, chkMovementSpeed, sigSpeedHackEnable, scSpeedHackEnable);
            // Name ESP offset güncelleme: 0x3A21F4 -> 0x3A21A8
            // Byte değişimi: 0x0F 0x84 (JE) -> 0xEB (JMP)
            R("Name ESP", "csh", 0x3A21A8, new byte[] { 0xEB }, chkNameESP, SignameESP, scNameESP);
            R("Speed Hack Value", "csh", 0x4373E8, BitConverter.GetBytes(SPEED_VALUE), chkMovementSpeed, sigSpeedHackValue, scSpeedHackValue);
            R("No Spread", "csh", 0x123834, new byte[] { 0x74 }, chkNoSpread, sigNoSpread, scNoSpread);

            R("WallShot 1", "wolf", 0x4F171, new byte[] { 0x05, 0, 0, 0, 0 }, chkWallShot, sigWallShot1, scWallShot1);
            R("WallShot 2", "wolf", 0x67533, new byte[] { 0x05, 0, 0, 0, 0 }, chkWallShot, sigWallShot2, scWallShot2);
            R("WallShot 3", "wolf", 0x59F8B, new byte[] { 0x05, 0, 0, 0, 0 }, chkWallShot, sigWallShot3, scWallShot3);
            R("WallShot 4", "wolf", 0x5A131, new byte[] { 0x05, 0, 0, 0, 0 }, chkWallShot, sigWallShot4, scWallShot4);
            R("NoClip", "wolf", 0x85F21, new byte[] { 0x0F, 0x85, 0xD3, 0x00 }, chkNoClip, sigNoClip, scNoClip);

            R("Swear Hack", "msvcr", 0x1339B, new byte[] { 0x75 }, chkSwearHack, sigSwearHack, scSwearHack);

            pNoSpread = patches.First(x => x.Name == "No Spread"); pNoSpread.CapLen = 2;
            pRapidFire = patches.First(x => x.Name == "Rapid Fire"); pRapidFire.CapLen = 2;

            // ---- YENI: 1-baytlik x87 FPU yamalari (FLD 0xD9 -> FADD 0xD8) ----
            // Offset yanlissa bayt 0xD9/0xD8 degil baska bir sey olur; uyari verilir.
            foreach (var p in patches)
                if (p.Bytes.Length == 1 && p.Bytes[0] == 0xD8) p.Orig = 0xD9;
        }

        void ApplyDefaultSigs()
        {
            foreach (var p in patches)
            {
                if (string.IsNullOrWhiteSpace(p.SigStr)) continue;   // bos -> 'Imza Uret' uretecek
                byte[] pat; bool[] mask;
                ParsePattern(p.SigStr, out pat, out mask);
                p.Sig = pat; p.SigMask = mask;
            }
        }

        void EnableDebugPrivilege()
        {
            IntPtr th;
            if (!OpenProcessToken(GetCurrentProcess(), 0x28, out th)) return;
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1 };
            tp.Privileges.Attributes = 0x2;
            LookupPrivilegeValue(null, "SeDebugPrivilege", out tp.Privileges.Luid);
            uint rl; AdjustTokenPrivileges(th, false, ref tp, 0, IntPtr.Zero, out rl);
            CloseHandle(th);
        }

        // ================= Baglanti =================
        void BtnConnect_Click()
        {
            try
            {
                var procs = Process.GetProcessesByName("WolfTeam").Concat(Process.GetProcessesByName("WolfTeam.bin")).ToArray();
                if (procs.Length == 0) { MessageBox.Show("WolfTeam acik degil!"); return; }
                target = procs[0]; pid = target.Id;
                IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid);
                if (h == IntPtr.Zero) h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, (uint)pid);
                if (h == IntPtr.Zero) { MessageBox.Show("OpenProcess basarisiz (Win32 " + Marshal.GetLastWin32Error() + "). Admin olarak calistir."); return; }
                CloseHandle(h);

                armed = false; btnArm.Text = "PATCH AC";
                RefreshModules(); TimerModules.Start(); TimerHack.Start(); UpdateStatus();
                txtModules.AppendText(">>> Baglandi. Once 'Imza Uret', sonra 'OFSET GUNCELLE (Sig)', sonra PATCH AC.\r\n");
            }
            catch (Exception ex) { MessageBox.Show("Hata: " + ex.Message); }
        }

        bool ProcessAlive() { try { return target != null && !target.HasExited; } catch { return false; } }

        void Disconnect()
        {
            TimerHack.Stop(); TimerModules.Stop();
            UnhookAll();
            target = null; pid = 0; hookAddr = IntPtr.Zero; armed = false;
            btnArm.Text = "PATCH AC";
            capHooks.Clear();
            foreach (var k in bases.Keys.ToList()) bases[k] = IntPtr.Zero;
            foreach (var p in patches)
            {
                p.Original = null; p.OriginalBase = IntPtr.Zero; p.Verified = false;
                p.WriteFailed = false; p.Relocated = false; p.Warned = false;
                if (p.Sc != null) p.Sc.Close();
            }
            lblStatus.Text = "Baglanti kesildi";
        }

        void UpdateStatus()
        {
            var s = "PID " + pid;
            foreach (var kv in bases) s += " | " + kv.Key + ":" + (kv.Value == IntPtr.Zero ? "--" : "OK");
            lblStatus.Text = s;
        }

        int ModuleSize(IntPtr h, IntPtr baseAddr)
        {
            try
            {
                int e = ReadI32(h, IntPtr.Add(baseAddr, 0x3C));
                if (e <= 0 || e > 0x1000) return 0;
                return ReadI32(h, IntPtr.Add(baseAddr, e + 24 + 56));
            }
            catch { return 0; }
        }

        int ReadI16(IntPtr h, IntPtr a) { var b = new byte[2]; UIntPtr n; return NtReadVirtualMemory(h, a, b, (UIntPtr)2, out n) == 0 ? BitConverter.ToInt16(b, 0) : 0; }
        int ReadI32(IntPtr h, IntPtr a) { var b = new byte[4]; UIntPtr n; return NtReadVirtualMemory(h, a, b, (UIntPtr)4, out n) == 0 ? BitConverter.ToInt32(b, 0) : 0; }
        string ReadStr(IntPtr h, IntPtr a, int max)
        {
            var b = new byte[max]; UIntPtr n;
            if (NtReadVirtualMemory(h, a, b, (UIntPtr)max, out n) != 0) return null;
            var s = Encoding.ASCII.GetString(b); int z = s.IndexOf('\0'); return z >= 0 ? s.Substring(0, z) : s;
        }

        string ReadImageName(IntPtr h, IntPtr baseAddr)
        {
            try
            {
                if (ReadI16(h, baseAddr) != 0x5A4D) return null;
                int e = ReadI32(h, IntPtr.Add(baseAddr, 0x3C));
                if (e <= 0 || e > 0x1000) return null;
                IntPtr pe = IntPtr.Add(baseAddr, e);
                if (ReadI32(h, pe) != 0x4550) return null;
                IntPtr opt = IntPtr.Add(pe, 24);
                int magic = ReadI16(h, opt);
                int ddOff = magic == 0x10B ? 96 : 112;
                int expRva = ReadI32(h, IntPtr.Add(opt, ddOff));
                if (expRva <= 0) return null;
                int nameRva = ReadI32(h, IntPtr.Add(baseAddr, expRva + 12));
                if (nameRva <= 0) return null;
                return ReadStr(h, IntPtr.Add(baseAddr, nameRva), 64);
            }
            catch { return null; }
        }

        void RefreshModules()
        {
            if (!ProcessAlive()) return;
            try { target.Refresh(); } catch { }
            var found = modulePatterns.Keys.ToDictionary(k => k, k => IntPtr.Zero);
            try
            {
                foreach (ProcessModule m in target.Modules)
                    foreach (var kv in modulePatterns)
                        if (found[kv.Key] == IntPtr.Zero && Regex.IsMatch(m.ModuleName, kv.Value, RegexOptions.IgnoreCase))
                            found[kv.Key] = m.BaseAddress;
            }
            catch { }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid);
            if (h != IntPtr.Zero)
            {
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
                            var name = ReadImageName(h, mbi.BaseAddress);
                            if (!string.IsNullOrEmpty(name))
                                foreach (var kv in modulePatterns)
                                    if (found[kv.Key] == IntPtr.Zero && Regex.IsMatch(name, kv.Value, RegexOptions.IgnoreCase))
                                        found[kv.Key] = mbi.BaseAddress;
                        }
                        addr = (IntPtr)(mbi.BaseAddress.ToInt64() + rs);
                    }
                }
                finally { CloseHandle(h); }
            }
            foreach (var kv in found) bases[kv.Key] = kv.Value;
        }

        void TimerModules_Tick()
        {
            if (!ProcessAlive()) { Disconnect(); return; }
            RefreshModules(); UpdateStatus();
        }

        void BtnScanModules_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Once baglan!"); return; }
            txtModules.Clear();
            try
            {
                txtModules.AppendText("=== PEB ===\r\n");
                target.Refresh();
                foreach (ProcessModule m in target.Modules)
                    txtModules.AppendText(m.ModuleName + "   @ 0x" + m.BaseAddress.ToInt64().ToString("X8") + "\r\n");
            }
            catch (Exception ex) { txtModules.AppendText("PEB hata: " + ex.Message + "\r\n"); }
        }

        void BtnArm_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Once Baglan!"); return; }
            armed = !armed;
            btnArm.Text = armed ? "PATCH KAPAT" : "PATCH AC";
            if (armed)
            {
                if (bases.Values.All(v => v == IntPtr.Zero))
                    MessageBox.Show("Hicbir modul tabani bulunamadi!\r\n'Moduller' ile kontrol et ve yonetici olarak calistir.");
                else txtModules.AppendText(">>> PATCH ACILDI\r\n");
            }
            else txtModules.AppendText(">>> PATCH KAPATILDI\r\n");
        }

        // ================= Ana dongu =================
        void TimerHack_Tick()
        {
            if (!ProcessAlive()) { Disconnect(); return; }
            if (!armed) return;

            foreach (var p in patches)
            {
                try
                {
                    var b = bases[p.ModKey]; if (b == IntPtr.Zero) continue;
                    var addr = IntPtr.Add(b, p.Offset);
                    var cur = StealthRead(addr, p.Bytes.Length); if (cur == null) continue;

                    if (p.Chk.Checked)
                    {
                        if (cur.SequenceEqual(p.Bytes)) { p.Verified = true; continue; }

                        // ---- YENI: offset dogrulama ----
                        // 1-baytlik FPU yamasinda beklenen orijinal bayt 0xD9'dur.
                        // Ne yama bayti ne de beklenen bayt ise offset kaymis demektir.
                        if (p.Orig != 0 && cur[0] != p.Bytes[0] && cur[0] != p.Orig && !p.Warned)
                        {
                            p.Warned = true;
                            txtModules.AppendText("[OFFSET SUPHELI] " + p.Name + " @ " + ModuleOf(addr) +
                                " bayt=0x" + cur[0].ToString("X2") + " (beklenen 0x" + p.Orig.ToString("X2") +
                                " / yama 0x" + p.Bytes[0].ToString("X2") + ") -> offset kaymis olabilir\r\n");
                        }

                        if (p.Sig != null && !SigMatchesAt(addr, p))
                        {
                            if (!p.Relocated && RelocEnabled && TryRelocate(p))
                            {
                                p.Relocated = true;
                                addr = IntPtr.Add(b, p.Offset);
                                cur = StealthRead(addr, p.Bytes.Length); if (cur == null) continue;
                                if (cur.SequenceEqual(p.Bytes)) { p.Verified = true; continue; }
                            }
                            else if (!RelocEnabled && !p.Warned)
                            {
                                p.Warned = true;
                                txtModules.AppendText("[SIG UYUSMUYOR | RELOC KAPALI] " + p.Name + " @ " + ModuleOf(addr) + "\r\n");
                            }
                        }

                        int cap = p.CapLen > 0 ? p.CapLen : p.Bytes.Length;
                        if (p.Original == null || p.OriginalBase != b || p.Original.Length < cap)
                        {
                            var raw = StealthRead(addr, cap);
                            if (raw != null) { p.Original = raw; p.OriginalBase = b; }
                        }

                        if (!StealthWrite(addr, p.Bytes))
                        {
                            if (!p.WriteFailed) { p.WriteFailed = true; txtModules.AppendText("[YAZILAMADI] " + p.Name + " @ " + ModuleOf(addr) + "\r\n"); }
                        }
                        else
                        {
                            if (!p.Verified)
                            {
                                p.Verified = true;
                                txtModules.AppendText("[YAZILDI] " + p.Name + " @ " + ModuleOf(addr) + " : " + BitConverter.ToString(p.Bytes) + "\r\n");
                            }
                            var back = StealthRead(addr, p.Bytes.Length);
                            if (back != null && !back.SequenceEqual(p.Bytes) && !p.Warned)
                            {
                                p.Warned = true;
                                txtModules.AppendText("[GERI ALINDI?] " + p.Name + " - bayt yazildiktan sonra degismis\r\n");
                            }
                        }
                    }
                    else
                    {
                        p.Verified = false; p.Relocated = false; p.WriteFailed = false; p.Warned = false;
                        if (p.Original != null && p.OriginalBase == b)
                        {
                            var c2 = StealthRead(addr, p.Original.Length);
                            if (c2 != null && c2.Take(p.Bytes.Length).SequenceEqual(p.Bytes)) StealthWrite(addr, p.Original);
                        }
                    }
                }
                catch (OutOfMemoryException) { GC.Collect(); }
                catch { }
            }
        }

        bool SigMatchesAt(IntPtr addr, Patch p)
        {
            if (p.Sig == null) return true;
            var cur = StealthRead(addr, p.Sig.Length);
            if (cur == null) return false;
            for (int i = 0; i < p.Sig.Length; i++) if (!p.SigMask[i] && cur[i] != p.Sig[i]) return false;
            return true;
        }

        // Mevcut offsetle birebir eslesen varsa o; yoksa EN YAKIN aday.
        IntPtr PickBestHit(List<IntPtr> hits, IntPtr b, int curOff)
        {
            foreach (var a in hits) if (a.ToInt32() - b.ToInt32() == curOff) return a;

            IntPtr best = hits[0];
            long bd = Math.Abs((long)(best.ToInt32() - b.ToInt32()) - curOff);
            foreach (var a in hits)
            {
                long d = Math.Abs((long)(a.ToInt32() - b.ToInt32()) - curOff);
                if (d < bd) { bd = d; best = a; }
            }
            return best;
        }

        bool TryRelocate(Patch p)
        {
            var b = bases[p.ModKey]; if (b == IntPtr.Zero || p.Sig == null) return false;
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return false;
            try
            {
                int size = ModuleSize(h, b); if (size == 0) return false;
                var hits = ScanPattern(p.Sig, p.SigMask, b, IntPtr.Add(b, size), 64);
                if (hits.Count == 0) return false;
                var best = PickBestHit(hits, b, p.Offset);
                int no = best.ToInt32() - b.ToInt32();
                if (no != p.Offset)
                {
                    txtModules.AppendText("[DEGISTI] " + p.Name + " " + p.Offset.ToString("X") + " -> " + no.ToString("X") + "\r\n");
                    p.Offset = no; p.Verified = false;
                    return true;
                }
                return false;
            }
            finally { CloseHandle(h); }
        }

        bool EnsureSig(Patch p)
        {
            if (p.Sig != null) return true;
            var b = bases[p.ModKey]; if (b == IntPtr.Zero) return false;
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return false;
            try
            {
                bool[] m;
                var sig = FindSig(h, p.ModKey, p.Offset, p.Bytes.Length, out m);
                if (sig == null) return false;
                p.Sig = sig; p.SigMask = m;
                p.SigStr = SigToStr(sig, m);
                return true;
            }
            finally { CloseHandle(h); }
        }

        // Imzayi, modul icinde TEK eslesme olana kadar bayt bayt uzatir.
        bool MakeSigUnique(Patch p)
        {
            var b = bases[p.ModKey]; if (b == IntPtr.Zero) return false;
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return false;
            try
            {
                int size = ModuleSize(h, b); if (size == 0) return false;
                var raw = StealthRead(IntPtr.Add(b, p.Offset), 64);
                if (raw == null) return false;

                for (int len = p.Bytes.Length + 3; len <= 48 && len <= raw.Length; len++)
                {
                    var sig = raw.Take(len).ToArray();
                    var m = new bool[len];
                    for (int i = 0; i < p.Bytes.Length && i < len; i++) m[i] = true;   // yama baytlari joker
                    var hits = ScanPattern(sig, m, b, IntPtr.Add(b, size), 8);
                    if (hits.Count == 1)
                    {
                        p.Sig = sig; p.SigMask = m; p.SigStr = SigToStr(sig, m);
                        return true;
                    }
                }
                return false;
            }
            finally { CloseHandle(h); }
        }

        void RestoreAll()
        {
            if (!ProcessAlive()) return;
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            try
            {
                foreach (var p in patches)
                {
                    if (p.Original == null) continue;
                    var b = bases[p.ModKey]; if (b == IntPtr.Zero || b != p.OriginalBase) continue;
                    var addr = IntPtr.Add(b, p.Offset);
                    var cur = StealthRead(addr, p.Original.Length);
                    if (cur != null && cur.Take(p.Bytes.Length).SequenceEqual(p.Bytes)) StealthWrite(addr, p.Original);
                }
            }
            finally { CloseHandle(h); }
        }

        // ================= Bellek =================
        byte[] StealthRead(IntPtr addr, int len)
        {
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return null;
            try { var buf = new byte[len]; UIntPtr n; return NtReadVirtualMemory(h, addr, buf, (UIntPtr)len, out n) == 0 && n.ToUInt64() == (ulong)len ? buf : null; }
            finally { CloseHandle(h); }
        }

        bool StealthWrite(IntPtr addr, byte[] data)
        {
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return false;
            try
            {
                long page = 0x1000;
                var pageStart = (IntPtr)(addr.ToInt64() & ~(page - 1));
                long span = (addr.ToInt64() - pageStart.ToInt64()) + data.Length;
                long pages = (span + page - 1) & ~(page - 1);
                var regionSize = (UIntPtr)(ulong)pages;
                var protAddr = pageStart; uint oldProt;
                bool ok = false;
                if (NtProtectVirtualMemory(h, ref protAddr, ref regionSize, PAGE_EXECUTE_READWRITE, out oldProt) == 0)
                {
                    UIntPtr w;
                    ok = NtWriteVirtualMemory(h, addr, data, (UIntPtr)data.Length, out w) == 0;
                    var protAddr2 = pageStart; var regionSize2 = (UIntPtr)(ulong)pages;
                    uint dummy; NtProtectVirtualMemory(h, ref protAddr2, ref regionSize2, oldProt, out dummy);
                }
                return ok;
            }
            finally { CloseHandle(h); }
        }

        bool WriteMem(IntPtr h, IntPtr addr, byte[] data)
        {
            uint op;
            if (!VirtualProtectEx(h, addr, (UIntPtr)data.Length, PAGE_EXECUTE_READWRITE, out op)) return false;
            UIntPtr w;
            bool ok = NtWriteVirtualMemory(h, addr, data, (UIntPtr)data.Length, out w) == 0;
            uint op2; VirtualProtectEx(h, addr, (UIntPtr)data.Length, op, out op2);
            return ok;
        }

        static bool IsHexChar(byte b) { return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F') || (b >= 'a' && b <= 'f'); }

        int IndexOf(byte[] buf, byte[] needle)
        {
            for (int i = 0; i <= buf.Length - needle.Length; i++) { bool ok = true; for (int j = 0; j < needle.Length; j++) if (buf[i + j] != needle[j]) { ok = false; break; } if (ok) return i; }
            return -1;
        }

        void ParsePattern(string s, out byte[] pat, out bool[] mask)
        {
            var parts = s.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            pat = new byte[parts.Length]; mask = new bool[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i] == "?" || parts[i] == "??") { mask[i] = true; pat[i] = 0; }
                else { mask[i] = false; pat[i] = Convert.ToByte(parts[i], 16); }
            }
        }

        string ModuleOf(IntPtr addr)
        {
            foreach (var kv in bases)
                if (kv.Value != IntPtr.Zero && addr.ToInt64() >= kv.Value.ToInt64() && addr.ToInt64() < kv.Value.ToInt64() + 0x2000000)
                    return kv.Key + "+" + ((uint)(addr.ToInt32() - kv.Value.ToInt32())).ToString("X");
            return "0x" + addr.ToInt64().ToString("X8");
        }

        // ================= Tarama =================
        void ScanRegionBuf(IntPtr h, byte[] buf, IntPtr regionBase, long regionSize, byte[] pat, bool[] mask, bool step4, List<IntPtr> res, int cap)
        {
            if (regionSize < pat.Length) return;
            long pos = 0;
            while (pos < regionSize)
            {
                if (res.Count >= cap) return;
                long take = Math.Min(SCAN_CHUNK, regionSize - pos);
                long readLen = Math.Min(take + pat.Length - 1, regionSize - pos);
                UIntPtr n;
                if (NtReadVirtualMemory(h, (IntPtr)(regionBase.ToInt64() + pos), buf, (UIntPtr)readLen, out n) != 0) { pos += take; continue; }
                long max = readLen - pat.Length;
                for (long i = 0; i <= max && i < take; i += (step4 ? 4 : 1))
                {
                    bool ok = true;
                    for (int j = 0; j < pat.Length; j++) if (!mask[j] && buf[i + j] != pat[j]) { ok = false; break; }
                    if (ok) { res.Add((IntPtr)(regionBase.ToInt64() + pos + i)); if (res.Count >= cap) return; }
                }
                pos += take;
            }
        }

        List<IntPtr> ScanPattern(byte[] pat, bool[] mask, IntPtr start, IntPtr end, int cap)
        {
            var res = new List<IntPtr>();
            if (pat == null || pat.Length == 0) return res;
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return res;
            try
            {
                var buf = new byte[SCAN_CHUNK + 64];
                IntPtr addr = start;
                MEMORY_BASIC_INFORMATION mbi; UIntPtr outLen;
                var sz = (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                while (addr.ToInt64() < end.ToInt64() && res.Count < cap)
                {
                    if (NtQueryVirtualMemory(h, addr, 0, out mbi, sz, out outLen) != 0) break;
                    long rs = (long)mbi.RegionSize.ToUInt64(); if (rs <= 0) break;
                    long lim = Math.Min(rs, end.ToInt64() - addr.ToInt64());
                    bool readable = mbi.State == MEM_COMMIT && (mbi.Protect & 0x01) == 0 && (mbi.Protect & 0x100) == 0;
                    if (readable && lim > 0) ScanRegionBuf(h, buf, addr, lim, pat, mask, false, res, cap);
                    addr = (IntPtr)(addr.ToInt64() + rs);
                }
            }
            finally { CloseHandle(h); }
            return res;
        }

        List<IntPtr> ScanAll(byte[] pat)
        {
            var res = new List<IntPtr>();
            if (pat == null || pat.Length == 0) return res;
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return res;
            try
            {
                var buf = new byte[SCAN_CHUNK + 64];
                var nomask = new bool[pat.Length];
                IntPtr addr = (IntPtr)0x10000;
                MEMORY_BASIC_INFORMATION mbi; UIntPtr outLen;
                var sz = (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                while (addr.ToInt64() < 0x7FFFFFFF)
                {
                    if (NtQueryVirtualMemory(h, addr, 0, out mbi, sz, out outLen) != 0) break;
                    long rs = (long)mbi.RegionSize.ToUInt64(); if (rs <= 0) break;
                    bool readable = mbi.State == MEM_COMMIT && (mbi.Protect & 0x01) == 0 && (mbi.Protect & 0x100) == 0;
                    if (readable) ScanRegionBuf(h, buf, mbi.BaseAddress, rs, pat, nomask, true, res, 300000);
                    addr = (IntPtr)(mbi.BaseAddress.ToInt64() + rs);
                }
            }
            finally { CloseHandle(h); }
            return res;
        }

        byte[] ParseValue()
        {
            if (scanIsFloat) return BitConverter.GetBytes(float.Parse(txtValue.Text, CultureInfo.InvariantCulture));
            return BitConverter.GetBytes(int.Parse(txtValue.Text));
        }

        void ShowHits()
        {
            txtModules.Clear();
            txtModules.AppendText("Bulunan: " + scanHits.Count + " adres\r\n");
            foreach (var a in scanHits.Take(300)) txtModules.AppendText(ModuleOf(a) + "\r\n");
        }

        void BtnScan1_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Baglan"); return; }
            scanIsFloat = chkFloat.Checked;
            txtModules.Clear(); txtModules.AppendText("Taraniyor...\r\n");
            scanHits = ScanAll(ParseValue());
            ShowHits();
        }

        void BtnScan2_Click()
        {
            if (scanHits.Count == 0) { MessageBox.Show("Once ILK TARAMA!"); return; }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            try
            {
                var pat = ParseValue(); var nh = new List<IntPtr>();
                foreach (var a in scanHits)
                {
                    var b = new byte[pat.Length]; UIntPtr n;
                    if (NtReadVirtualMemory(h, a, b, (UIntPtr)pat.Length, out n) == 0 && b.SequenceEqual(pat)) nh.Add(a);
                }
                scanHits = nh; ShowHits();
            }
            finally { CloseHandle(h); }
        }

        void BtnAoB_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Once baglan!"); return; }
            byte[] pat; bool[] mask;
            try { ParsePattern(txtPattern.Text, out pat, out mask); } catch { MessageBox.Show("Pattern hatali"); return; }
            var mod = txtAoBMod.Text.Trim().ToLower();
            if (!bases.ContainsKey(mod) || bases[mod] == IntPtr.Zero) { MessageBox.Show("Modul yok: " + mod); return; }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            int size = ModuleSize(h, bases[mod]); CloseHandle(h);
            txtModules.Clear(); txtModules.AppendText("AoB taraniyor (" + mod + ")...\r\n");
            var hits = ScanPattern(pat, mask, bases[mod], IntPtr.Add(bases[mod], size), 500);
            txtModules.Clear();
            txtModules.AppendText("Bulunan: " + hits.Count + "\r\n");
            foreach (var a in hits.Take(300)) txtModules.AppendText(ModuleOf(a) + "\r\n");
        }

        // ================= Imza =================
        byte[] FindSig(IntPtr h, string modKey, int offset, int maskHead, out bool[] mask)
        {
            mask = null;
            var b = bases[modKey]; if (b == IntPtr.Zero) return null;
            int size = ModuleSize(h, b); if (size == 0) return null;
            var raw = StealthRead(IntPtr.Add(b, offset), 40);
            if (raw == null) return null;
            for (int len = 6; len <= 32; len++)
            {
                var sig = raw.Take(len).ToArray();
                var m = new bool[len];
                for (int i = 0; i < maskHead && i < len; i++) m[i] = true;
                var hits = ScanPattern(sig, m, b, IntPtr.Add(b, size), 8);
                if (hits.Count == 1) { mask = m; return sig; }
            }
            var fb = raw.Take(32).ToArray();
            mask = new bool[fb.Length];
            for (int i = 0; i < maskHead && i < fb.Length; i++) mask[i] = true;
            return fb;
        }

        static string SigToStr(byte[] sig, bool[] mask)
        {
            return string.Join(" ", sig.Select((x, i) => (mask != null && mask[i]) ? "??" : x.ToString("X2")));
        }

        // p.Sc = bu yamanin KENDI tarayicisi
        List<IntPtr> ScanWith(Patch p, int cap)
        {
            var res = new List<IntPtr>();
            if (p.Sig == null || p.Sc == null) return res;
            if (p.Sc.Proc == null || p.Sc.Proc.HasExited)
                if (!p.Sc.GetProcess("WolfTeam.bin")) return res;
            var mod = p.Sc.GetModule(modulePatterns[p.ModKey]);
            if (mod == null) return res;
            return p.Sc.FindAll(mod.BaseAddress, IntPtr.Add(mod.BaseAddress, mod.ModuleMemorySize), p.Sig, p.SigMask, cap);
        }

        void BtnSig_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Baglan"); return; }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            txtModules.Clear(); txtModules.AppendText("Imzalar uretiliyor (TEK olana kadar uzatilir)...\r\n");
            try
            {
                int ok = 0, multi = 0, fail = 0;
                foreach (var p in patches)
                {
                    var b = bases[p.ModKey]; if (b == IntPtr.Zero) { fail++; continue; }

                    // ---- YENI: elle yazilmis (sabit) imzayi EZME ----
                    if (!string.IsNullOrWhiteSpace(p.SigStr) && p.Sig != null)
                    {
                        var hs = ScanWith(p, 8);
                        if (hs.Count == 1) ok++; else multi++;
                        txtModules.AppendText(p.Name.PadRight(20) + " [SABIT imza korundu] " + p.SigStr + "\r\n");
                        continue;
                    }

                    bool[] m;
                    var sig = FindSig(h, p.ModKey, p.Offset, p.Bytes.Length, out m);
                    if (sig == null) { fail++; continue; }
                    p.Sig = sig; p.SigMask = m;
                    p.SigStr = SigToStr(sig, m);

                    var hits = ScanWith(p, 8);
                    if (hits.Count == 1) ok++; else multi++;
                    txtModules.AppendText(p.Name.PadRight(20) + " [" + (hits.Count == 1 ? "TEK" : hits.Count + " adet") + "]  " + p.SigStr + "\r\n");
                    if (hits.Count > 1)
                        foreach (var hh in hits.Take(5))
                            txtModules.AppendText("          aday: " + ModuleOf(hh) + (hh.ToInt32() - b.ToInt32() == p.Offset ? "   <= mevcut" : "") + "\r\n");
                }
                txtModules.AppendText("\r\nTEK: " + ok + "  coklu: " + multi + "  hata: " + fail + "\r\n");
                txtModules.AppendText("(Bastaki '??' = yama o bayti degistiriyor, normaldir.)\r\n");
            }
            finally { CloseHandle(h); }
        }

        // =====================================================================
        //  IMZADAN OFSET GUNCELLEME
        //  Resimdeki akisin aynisi:
        //     GetProcess -> GetModule -> FindSignature -> (adres - base) = offset
        // =====================================================================
        int ResolveOffset(Patch p, out int newOffset, out bool exact, out bool confident)
        {
            newOffset = p.Offset; exact = false; confident = false;
            if (p.Sig == null || p.Sc == null) return 0;

            if (p.Sc.Proc == null || p.Sc.Proc.HasExited)
                if (!p.Sc.GetProcess("WolfTeam.bin")) return 0;

            var mod = p.Sc.GetModule(modulePatterns[p.ModKey]);
            if (mod == null) return 0;

            IntPtr baseAddr = mod.BaseAddress;
            IntPtr endAddr = IntPtr.Add(baseAddr, mod.ModuleMemorySize);
            var hits = p.Sc.FindAll(baseAddr, endAddr, p.Sig, p.SigMask, 64);
            if (hits.Count == 0) return 0;

            foreach (var a in hits)
                if (a.ToInt32() - baseAddr.ToInt32() == p.Offset) { exact = true; break; }

            IntPtr best = PickBestHit(hits, baseAddr, p.Offset);
            newOffset = best.ToInt32() - baseAddr.ToInt32();

            // ---- YENI: guven degerlendirmesi ----
            // Tek eslesme / birebir eslesme / en yakin aday ikinciden belirgin sekilde
            // yakinsa (ayni imzayi paylasan yamalar icin) kabul edilir.
            if (hits.Count == 1 || exact) confident = true;
            else
            {
                long d1 = long.MaxValue, d2 = long.MaxValue;
                foreach (var a in hits)
                {
                    long d = Math.Abs((long)(a.ToInt32() - baseAddr.ToInt32()) - p.Offset);
                    if (d < d1) { d2 = d1; d1 = d; }
                    else if (d < d2) d2 = d;
                }
                confident = d1 == 0 || d1 * 3 < d2;
            }
            return hits.Count;
        }

        void UpdateOffsetsFromSigs()
        {
            if (!ProcessAlive()) { MessageBox.Show("Once Baglan!"); return; }
            RefreshModules();
            txtModules.Clear();
            txtModules.AppendText("=== IMZADAN OFSET GUNCELLEME ===\r\n");

            int tek = 0, cok = 0, hata = 0, degisen = 0, supheli = 0, uzatilan = 0;

            foreach (var p in patches)
            {
                if (bases[p.ModKey] == IntPtr.Zero)
                { hata++; txtModules.AppendText(p.Name.PadRight(20) + " [modul yok]\r\n"); continue; }

                if (p.Sig == null && !EnsureSig(p))
                { hata++; txtModules.AppendText(p.Name.PadRight(20) + " [imza yok]\r\n"); continue; }

                int yeni; bool exact, conf;
                int adet = ResolveOffset(p, out yeni, out exact, out conf);

                // belirsizse ve guven yoksa imzayi uzat, tekrar dene
                if (adet > 1 && !conf && MakeSigUnique(p))
                {
                    uzatilan++;
                    adet = ResolveOffset(p, out yeni, out exact, out conf);
                    txtModules.AppendText(p.Name.PadRight(20) + " [IMZA UZATILDI] " + p.SigStr + "\r\n");
                }

                if (adet == 0)
                { hata++; txtModules.AppendText(p.Name.PadRight(20) + " [BULUNAMADI]\r\n"); continue; }

                string tag = adet > 1 ? "   [COKLU " + adet + "]" : "";

                if (adet == 1 || exact || conf)
                {
                    if (yeni == p.Offset)
                        txtModules.AppendText(p.Name.PadRight(20) + " " + p.Offset.ToString("X") + " (ayni)" + tag + "\r\n");
                    else
                    {
                        txtModules.AppendText(p.Name.PadRight(20) + " " + p.Offset.ToString("X") +
                                              " -> " + yeni.ToString("X") + "  *GUNCELLENDI*" + tag + "\r\n");
                        p.Offset = yeni; p.Verified = false; p.Relocated = false;
                        degisen++;
                    }
                    if (adet == 1) tek++; else cok++;
                }
                else
                {
                    supheli++;
                    txtModules.AppendText(p.Name.PadRight(20) + " " + p.Offset.ToString("X") +
                                          " (SUPHELI, aday: " + yeni.ToString("X") + ")" + tag + "\r\n");
                }
            }

            txtModules.AppendText("\r\nToplam: " + patches.Count + "  TEK: " + tek + "  COKLU: " + cok +
                                  "  UZATILAN: " + uzatilan + "  DEGISEN: " + degisen +
                                  "  SUPHELI: " + supheli + "  hata: " + hata + "\r\n");
            if (supheli > 0)
                txtModules.AppendText("SUPHELI olanlar icin 'Imza Uret' calistir.\r\n");

            SaveOffsets();
            txtModules.AppendText(">>> offsets.txt kaydedildi.\r\n");
        }

        // ================= Offset kaliciligi =================
        void SaveOffsets()
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("# WolfBypass offsets - " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
                foreach (var p in patches) sb.AppendLine(p.Name + "=" + p.Offset.ToString("X"));
                File.WriteAllText(offFile, sb.ToString());
            }
            catch { }
        }

        void LoadOffsets()
        {
            try
            {
                if (!File.Exists(offFile)) return;
                var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                foreach (var line in File.ReadAllLines(offFile))
                {
                    if (line.StartsWith("#")) continue;
                    int eq = line.IndexOf('='); if (eq <= 0) continue;
                    int v;
                    if (int.TryParse(line.Substring(eq + 1).Trim(), NumberStyles.HexNumber,
                                     CultureInfo.InvariantCulture, out v))
                        map[line.Substring(0, eq).Trim()] = v;
                }
                foreach (var p in patches)
                {
                    int v;
                    if (map.TryGetValue(p.Name, out v)) p.Offset = v;
                }
            }
            catch { }
        }

        void ResetOffsets()
        {
            foreach (var p in patches) { p.Offset = p.DefOffset; p.Verified = false; p.Relocated = false; }
            try { if (File.Exists(offFile)) File.Delete(offFile); } catch { }
            txtModules.AppendText(">>> Offsetler koddaki varsayilanlara dondu.\r\n");
        }

        // Koda yapistirmalik cikti
        void DumpOffsetsCode()
        {
            if (!ProcessAlive()) { MessageBox.Show("Once Baglan!"); return; }
            var sb = new StringBuilder();
            sb.AppendLine("// ==== BuildPatchList icin guncel offsetler ====");
            foreach (var p in patches)
            {
                string bytes = "new byte[] { " + string.Join(", ", p.Bytes.Select(x => "0x" + x.ToString("X2"))) + " }";
                sb.AppendLine("R(\"" + p.Name + "\", \"" + p.ModKey + "\", 0x" + p.Offset.ToString("X") +
                              ", " + bytes + ", " + VarName(p.Chk) + ", " + SigVarName(p) + ", " + ScVarName(p) + ");");
            }
            txtModules.AppendText("\r\n" + sb.ToString());
            try { File.WriteAllText(Path.Combine(Application.StartupPath, "offsets_code.txt"), sb.ToString()); } catch { }
        }

        string VarName(object val)
        {
            foreach (var f in GetType().GetFields(BindingFlags.NonPublic | BindingFlags.Instance))
                if (f.FieldType == typeof(CheckBox) && object.ReferenceEquals(f.GetValue(this), val)) return f.Name;
            return "chkX";
        }
        string SigVarName(Patch p)
        {
            if (string.IsNullOrEmpty(p.SigStr)) return "\"\"";
            foreach (var f in GetType().GetFields(BindingFlags.NonPublic | BindingFlags.Instance))
                if (f.FieldType == typeof(string) && object.ReferenceEquals(f.GetValue(this), p.SigStr)) return f.Name;
            return "\"" + p.SigStr + "\"";
        }
        string ScVarName(Patch p)
        {
            foreach (var f in GetType().GetFields(BindingFlags.NonPublic | BindingFlags.Instance))
                if (f.FieldType == typeof(SignatureScanner) && object.ReferenceEquals(f.GetValue(this), p.Sc)) return f.Name;
            return "new SignatureScanner()";
        }

        // Resimdeki main() akisinin aynisi (tek imza, manuel test)
        void OrnekAkis()
        {
            // //////////////////////////////////////////////////////
            // Burada Signaturelerimizi Tanimlayacagiz.
            // //////////////////////////////////////////////////////
            const string OrnekSignature  = "?? ?? ?? ?? 00 00 34";   // No Recoil
            const string OrnekSignature1 = "?? 10 8D 4D CC B3 01";   // No Spread
            const string OrnekSignature2 = "74 3F 8B D1 2B C3";      // Swear Hack
            const string OrnekSignature3 = "00 FF D6 68 CC 62";      // NoClip
            const string Mask            = "xxxxxxxx";

            SignatureScanner OrnSigTara1 = new SignatureScanner();
            //SignatureScanner OrnSigTara2 = new SignatureScanner();
            //SignatureScanner OrnSigTara3 = new SignatureScanner();
            //SignatureScanner OrnSigTara4 = new SignatureScanner();

            if (OrnSigTara1.GetProcess("WolfTeam.bin"))
            {
                var mod = OrnSigTara1.GetModule(@"csh[a-z0-9]*\.tmp|CShell\.dll");
                if (mod == null) { txtModules.AppendText("modul yok\r\n"); return; }

                IntPtr OrnekSigArat = OrnSigTara1.Find(mod.BaseAddress,
                                                       IntPtr.Add(mod.BaseAddress, mod.ModuleMemorySize),
                                                       OrnekSignature, Mask);

                int OrnekSignatureDeger = OrnSigTara1.Read<int>(OrnekSigArat);

                txtModules.AppendText("Sonuc : " + ModuleOf(OrnekSigArat) +
                                      "  deger=" + OrnekSignatureDeger +
                                      "  offset=" + (OrnekSigArat.ToInt32() - mod.BaseAddress.ToInt32()).ToString("X") +
                                      "\r\n");
            }
        }

        void BtnScanAll_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Baglan"); return; }
            txtModules.Clear(); txtModules.AppendText("Toplu tarama...\r\n");
            int ok = 0, none = 0;
            foreach (var p in patches)
            {
                if (bases[p.ModKey] == IntPtr.Zero) { none++; continue; }
                if (p.Sig == null && !EnsureSig(p)) { none++; continue; }
                int yeni; bool exact, conf;
                int adet = ResolveOffset(p, out yeni, out exact, out conf);
                if (adet == 0) { none++; txtModules.AppendText(p.Name.PadRight(20) + " [YOK]\r\n"); continue; }
                if (adet == 1 || exact || conf) { p.Offset = yeni; p.Verified = false; ok++; }
                txtModules.AppendText(p.Name.PadRight(20) + " " + p.Offset.ToString("X") + (adet > 1 ? " [COKLU " + adet + "]" : "") + "\r\n");
            }
            txtModules.AppendText("\r\nOK: " + ok + "  yok: " + none + "\r\n");
        }

        void BtnValidate_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Baglan"); return; }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            txtModules.Clear(); txtModules.AppendText("Dogrulama (yazma YOK)...\r\n");
            try
            {
                int ok = 0, bad = 0, unk = 0;
                foreach (var p in patches)
                {
                    var b = bases[p.ModKey];
                    if (b == IntPtr.Zero) { txtModules.AppendText(p.Name.PadRight(20) + " [modul yok]\r\n"); unk++; continue; }
                    if (p.Sig == null)
                    {
                        var raw = StealthRead(IntPtr.Add(b, p.Offset), 16);
                        txtModules.AppendText(p.Name.PadRight(20) + " [imza yok] " + p.ModKey + "+" + p.Offset.ToString("X") + " : " + (raw == null ? "?" : BitConverter.ToString(raw)) + "\r\n");
                        unk++; continue;
                    }
                    int len = Math.Max(p.Sig.Length, p.Bytes.Length);
                    var cur = StealthRead(IntPtr.Add(b, p.Offset), len);
                    if (cur == null) { txtModules.AppendText(p.Name.PadRight(20) + " [okunamadi]\r\n"); unk++; continue; }
                    bool sigOk = true;
                    for (int i = 0; i < p.Sig.Length; i++) if (!p.SigMask[i] && cur[i] != p.Sig[i]) { sigOk = false; break; }
                    bool patched = true;
                    for (int i = 0; i < p.Bytes.Length; i++) if (cur[i] != p.Bytes[i]) { patched = false; break; }
                    if (sigOk || patched) { ok++; txtModules.AppendText(p.Name.PadRight(20) + "  OK" + (patched ? " (uygulanmis)" : "") + "\r\n"); }
                    else { bad++; txtModules.AppendText(p.Name.PadRight(20) + "  UYUSMUYOR -> " + BitConverter.ToString(cur) + "\r\n"); }
                }
                txtModules.AppendText("\r\nUyumlu: " + ok + "  Supheli: " + bad + "  Bilinmez: " + unk + "\r\n");
            }
            finally { CloseHandle(h); }
        }

        void BtnDump_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Baglan"); return; }
            var parts = txtPtrBase.Text.Split('+');
            if (parts.Length != 2) { MessageBox.Show("txtPtrBase'e modul+offset yaz (or. csh+123834)"); return; }
            var mod = parts[0].Trim().ToLower();
            if (!bases.ContainsKey(mod) || bases[mod] == IntPtr.Zero) { MessageBox.Show("Modul yok"); return; }
            int off;
            try { off = Convert.ToInt32(parts[1], 16); } catch { MessageBox.Show("Offset hatali"); return; }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            try
            {
                var buf = new byte[128]; UIntPtr n;
                if (NtReadVirtualMemory(h, IntPtr.Add(bases[mod], off), buf, (UIntPtr)128, out n) != 0) { MessageBox.Show("okunamadi"); return; }
                txtModules.AppendText("\r\n" + mod + "+" + off.ToString("X") + " (128b):\r\n" + BitConverter.ToString(buf) + "\r\n");
            }
            finally { CloseHandle(h); }
        }

        IntPtr ReadPtrChain(IntPtr h, IntPtr baseAddr, int[] offs)
        {
            IntPtr cur = baseAddr;
            for (int i = 0; i < offs.Length; i++)
            {
                var buf = new byte[4]; UIntPtr n;
                if (NtReadVirtualMemory(h, IntPtr.Add(cur, offs[i]), buf, (UIntPtr)4, out n) != 0) return IntPtr.Zero;
                cur = (IntPtr)BitConverter.ToInt32(buf, 0);
            }
            return cur;
        }

        void BtnPtrRead_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Baglan"); return; }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            try
            {
                var parts = txtPtrBase.Text.Split('+');
                if (parts.Length != 2) { MessageBox.Show("Base formati: modul+offset"); return; }
                var mod = parts[0].Trim().ToLower();
                if (!bases.ContainsKey(mod) || bases[mod] == IntPtr.Zero) { MessageBox.Show("Modul yok"); return; }
                int baseOff = Convert.ToInt32(parts[1], 16);
                var offs = txtPtrOffs.Text.Split(',').Where(x => x.Trim().Length > 0).Select(x => Convert.ToInt32(x.Trim(), 16)).ToArray();
                var final = ReadPtrChain(h, IntPtr.Add(bases[mod], baseOff), offs);
                if (final == IntPtr.Zero) { MessageBox.Show("Zincir okunamadi"); return; }
                var b = new byte[4]; UIntPtr n;
                NtReadVirtualMemory(h, final, b, (UIntPtr)4, out n);
                txtModules.AppendText("\r\nPointer: " + ModuleOf(final) + "  deger=" + BitConverter.ToInt32(b, 0) + "\r\n");
            }
            finally { CloseHandle(h); }
        }

        // ================= CRC / hook =================
        List<IntPtr> FindCodeRefs()
        {
            var res = new List<IntPtr>();
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return res;
            try
            {
                var b = bases["csh"]; if (b == IntPtr.Zero) return res;
                int size = ModuleSize(h, b); if (size == 0) return res;
                var buf = new byte[size]; UIntPtr n;
                NtReadVirtualMemory(h, b, buf, (UIntPtr)size, out n);
                var needle = Encoding.ASCII.GetBytes("CS_CH_LOGIN_REQ");
                int off = IndexOf(buf, needle); if (off < 0) return res;
                int strAddr = b.ToInt32() + off; var r = BitConverter.GetBytes(strAddr);
                for (int i = 0; i <= size - 5; i++)
                {
                    if (buf[i] == 0x68 && buf[i + 1] == r[0] && buf[i + 2] == r[1] && buf[i + 3] == r[2] && buf[i + 4] == r[3]) res.Add((IntPtr)(b.ToInt32() + i));
                    else if (buf[i] >= 0xB8 && buf[i] <= 0xBF && buf[i + 1] == r[0] && buf[i + 2] == r[1] && buf[i + 3] == r[2] && buf[i + 4] == r[3]) res.Add((IntPtr)(b.ToInt32() + i));
                }
            }
            finally { CloseHandle(h); }
            return res;
        }

        IntPtr WalkBackToFunc(IntPtr h, IntPtr addr)
        {
            long a = addr.ToInt64(); var b = new byte[6]; UIntPtr n;
            for (long i = 0; i < 4000; i++)
            {
                if (a - i < 0x10000) break;
                NtReadVirtualMemory(h, (IntPtr)(a - i), b, (UIntPtr)6, out n);
                if (b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC) return (IntPtr)(a - i);
                if (b[0] == 0x8B && b[1] == 0xFF && b[2] == 0x55 && b[3] == 0x8B && b[4] == 0xEC) return (IntPtr)(a - i + 2);
            }
            return IntPtr.Zero;
        }

        static int InsnLen(byte[] b, int start)
        {
            int p = start;
            while (p < b.Length)
            {
                byte x = b[p];
                if (x == 0x66 || x == 0x67 || x == 0xF0 || x == 0xF2 || x == 0xF3 ||
                    x == 0x2E || x == 0x36 || x == 0x3E || x == 0x26 || x == 0x64 || x == 0x65) p++;
                else break;
            }
            if (p >= b.Length) return 1;
            byte op = b[p]; p++;
            bool modrm = false, imm8 = false, immZ = false, rel8 = false, relZ = false;

            if (op == 0x0F)
            {
                if (p >= b.Length) return p - start;
                byte o2 = b[p]; p++;
                if (o2 >= 0x80 && o2 <= 0x8F) relZ = true; else modrm = true;
            }
            else if ((op & 0xF8) == 0x50 || (op & 0xF8) == 0x58 || (op & 0xF8) == 0x40) { }
            else if ((op & 0xF8) == 0xB8) immZ = true;
            else if ((op & 0xF8) == 0xB0) imm8 = true;
            else if (op >= 0x70 && op <= 0x7F) rel8 = true;
            else if (op == 0xEB) rel8 = true;
            else if (op == 0xE9 || op == 0xE8) relZ = true;
            else if (op == 0xA0 || op == 0xA1 || op == 0xA2 || op == 0xA3) immZ = true;
            else if (op == 0x68) immZ = true;
            else if (op == 0x6A) imm8 = true;
            else if (op == 0xC2) immZ = true;
            else if (op == 0xC3 || op == 0x90 || op == 0x98 || op == 0x99 || op == 0xCC || op == 0x9C || op == 0x9D) { }
            else if (op == 0xC6) { modrm = true; imm8 = true; }
            else if (op == 0xC7) { modrm = true; immZ = true; }
            else if (op == 0x80 || op == 0x82 || op == 0x83) { modrm = true; imm8 = true; }
            else if (op == 0x81) { modrm = true; immZ = true; }
            else if (op == 0xF6 || op == 0xF7)
            {
                if (p < b.Length) { byte m = b[p]; modrm = true; int reg = (m >> 3) & 7; if (reg == 0 || reg == 1) { if (op == 0xF6) imm8 = true; else immZ = true; } }
            }
            else if (op == 0xFE || op == 0xFF) modrm = true;
            else if ((op & 0xFC) == 0x00 || (op & 0xFC) == 0x08 || (op & 0xFC) == 0x10 || (op & 0xFC) == 0x18 ||
                     (op & 0xFC) == 0x20 || (op & 0xFC) == 0x28 || (op & 0xFC) == 0x30 || (op & 0xFC) == 0x38) modrm = true;
            else if (op == 0x84 || op == 0x85 || op == 0x86 || op == 0x87 || op == 0x88 || op == 0x89 ||
                     op == 0x8A || op == 0x8B || op == 0x8D || op == 0x8F || op == 0x62 || op == 0x63) modrm = true;
            else if (op == 0x69) { modrm = true; immZ = true; }
            else if (op == 0x6B) { modrm = true; imm8 = true; }
            else if (op == 0xD1 || op == 0xD3 || op == 0xC0) modrm = true;
            else if (op == 0xC1) { modrm = true; imm8 = true; }
            else if (op == 0xD0 || op == 0xD2) modrm = true;
            else if (op == 0x8E || op == 0x8C) modrm = true;

            if (modrm && p < b.Length)
            {
                byte m = b[p]; p++;
                int mod = (m >> 6) & 3, rm = m & 7;
                if (mod != 3)
                {
                    if (rm == 4) { if (p < b.Length) { byte sib = b[p]; p++; if (((sib >> 6) & 3) == 0 && (sib & 7) == 5) p += 4; } }
                    else if (rm == 5 && mod == 0) p += 4;
                    if (mod == 1) p += 1;
                    else if (mod == 2) p += 4;
                }
            }
            if (imm8) p += 1;
            if (immZ) p += 4;
            if (rel8) p += 1;
            if (relZ) p += 4;
            return p - start;
        }

        bool InstallCap(IntPtr h, IntPtr f)
        {
            var head = new byte[16]; UIntPtr n;
            if (NtReadVirtualMemory(h, f, head, (UIntPtr)16, out n) != 0) return false;
            int p = 0;
            while (p < 5) { int l = InsnLen(head, p); if (l <= 0) l = 1; p += l; if (p > 15) return false; }
            int codeLen = 32 + p + 8;
            var mem = VirtualAllocEx(h, IntPtr.Zero, (UIntPtr)codeLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (mem == IntPtr.Zero) return false;
            var slot = mem;
            int c = 8;
            var code = new byte[codeLen];
            Array.Copy(head, 0, code, c, p);
            code[c + p] = 0xA3; BitConverter.GetBytes(slot.ToInt32()).CopyTo(code, c + p + 1);
            int j = c + p + 5;
            code[j] = 0xE9;
            BitConverter.GetBytes((f.ToInt32() + p) - (mem.ToInt32() + j + 5)).CopyTo(code, j + 1);
            WriteMem(h, mem, code);

            var orig5 = new byte[5]; Array.Copy(head, 0, orig5, 0, 5);
            var jmp = new byte[5]; jmp[0] = 0xE9;
            BitConverter.GetBytes((mem.ToInt32() + c) - (f.ToInt32() + 5)).CopyTo(jmp, 1);
            WriteMem(h, f, jmp);

            activeHooks.Add(new ActiveHook { Target = f, Orig5 = orig5, Cave = mem });
            capHooks.Add(new CapHook { Slot = slot });
            return true;
        }

        bool InstallCrcHook(IntPtr f, string expectedCrc, int retBytes)
        {
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return false;
            try
            {
                var orig5 = new byte[5]; UIntPtr n;
                if (NtReadVirtualMemory(h, f, orig5, (UIntPtr)5, out n) != 0) return false;

                var strBytes = Encoding.ASCII.GetBytes(expectedCrc + "\0");
                int total = 8 + strBytes.Length;
                var mem = VirtualAllocEx(h, IntPtr.Zero, (UIntPtr)total, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (mem == IntPtr.Zero) return false;
                var strAddr = IntPtr.Add(mem, 8);
                var stub = new byte[8];
                stub[0] = 0xB8; BitConverter.GetBytes(strAddr.ToInt32()).CopyTo(stub, 1);
                stub[5] = 0xC2; stub[6] = (byte)(retBytes & 0xFF); stub[7] = (byte)((retBytes >> 8) & 0xFF);
                WriteMem(h, mem, stub);
                WriteMem(h, strAddr, strBytes);

                var jmp = new byte[5]; jmp[0] = 0xE9;
                BitConverter.GetBytes(mem.ToInt32() - (f.ToInt32() + 5)).CopyTo(jmp, 1);
                WriteMem(h, f, jmp);

                activeHooks.Add(new ActiveHook { Target = f, Orig5 = orig5, Cave = mem });
                return true;
            }
            finally { CloseHandle(h); }
        }

        void BtnHook_Click()
        {
            if (bases["csh"] == IntPtr.Zero) { MessageBox.Show("csh yok!"); return; }
            UnhookAll();
            var crc = string.IsNullOrWhiteSpace(txtCrc.Text) ? candidates[hookIdx++ % candidates.Count] : txtCrc.Text.Trim();
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            try
            {
                var refs = FindCodeRefs(); if (refs.Count == 0) { MessageBox.Show("Referans yok"); return; }
                var f = WalkBackToFunc(h, refs[0]); if (f == IntPtr.Zero) { MessageBox.Show("Fonksiyon yok"); return; }
                int retBytes = 0; int.TryParse(txtRet.Text, out retBytes);
                bool ok = InstallCrcHook(f, crc, retBytes);
                txtModules.AppendText("\r\n>>> HOOK " + (ok ? "KURULDU" : "BASARISIZ") + " ret=" + retBytes + " crc=" + crc + "\r\n");
                if (ok) hookAddr = f;
            }
            finally { CloseHandle(h); }
        }

        void BtnCapture_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Baglan"); return; }
            UnhookAll();
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            try
            {
                var refs = FindCodeRefs(); if (refs.Count == 0) { MessageBox.Show("Referans yok"); return; }
                var f = WalkBackToFunc(h, refs[0]); if (f == IntPtr.Zero) { MessageBox.Show("Fonksiyon yok"); return; }
                bool ok = InstallCap(h, f);
                txtModules.AppendText("\r\n>>> CAPTURE " + (ok ? "KURULDU" : "BASARISIZ") + " -> login/logout yap, sonra 'CRC Oku'.\r\n");
                if (ok) hookAddr = f;
            }
            finally { CloseHandle(h); }
        }

        void BtnCapAll_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Baglan"); return; }
            UnhookAll();
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            try
            {
                var refs = FindCodeRefs(); if (refs.Count == 0) { MessageBox.Show("Referans yok"); return; }
                var f = WalkBackToFunc(h, refs[0]); if (f == IntPtr.Zero) { MessageBox.Show("Fonksiyon yok"); return; }
                var body = new byte[2500]; UIntPtr n;
                if (NtReadVirtualMemory(h, f, body, (UIntPtr)2500, out n) != 0) return;
                var seen = new HashSet<int>(); int cnt = 0;
                for (int i = 0; i < body.Length - 5; i++)
                {
                    if (body[i] == 0xE8)
                    {
                        int rel = BitConverter.ToInt32(body, i + 1);
                        int t = f.ToInt32() + i + 5 + rel;
                        if (t > 0x10000 && seen.Add(t)) { if (InstallCap(h, (IntPtr)t)) cnt++; }
                    }
                }
                txtModules.AppendText("\r\n>>> " + cnt + " fonksiyon yakalandi. Login/logout yap, sonra 'CRC Oku'.\r\n");
            }
            finally { CloseHandle(h); }
        }

        void BtnReadCrc_Click()
        {
            if (capHooks.Count == 0) { MessageBox.Show("Once CAPTURE ya da Tum Call Yakala"); return; }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            txtModules.AppendText("\r\n--- okunuyor ---\r\n");
            try
            {
                foreach (var c in capHooks)
                {
                    var p = new byte[4]; UIntPtr n;
                    NtReadVirtualMemory(h, c.Slot, p, (UIntPtr)4, out n);
                    int ptr = BitConverter.ToInt32(p, 0);
                    if (ptr == 0) continue;
                    var s = new byte[64];
                    NtReadVirtualMemory(h, (IntPtr)ptr, s, (UIntPtr)64, out n);
                    var str = Encoding.ASCII.GetString(s);
                    int z = str.IndexOf('\0'); if (z >= 0) str = str.Substring(0, z);
                    bool isHex32 = str.Length == 32 && str.All(ch => "0123456789abcdefABCDEF".IndexOf(ch) >= 0);
                    txtModules.AppendText((isHex32 ? "[CRC] " : "      ") + str + "\r\n");
                }
            }
            finally { CloseHandle(h); }
        }

        List<string> ScanHex32(IntPtr h)
        {
            var res = new List<string>(); var seen = new HashSet<string>();
            IntPtr addr = (IntPtr)0x10000; MEMORY_BASIC_INFORMATION mbi; UIntPtr outLen;
            var sz = (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            while (addr.ToInt64() < 0x7FFFFFFF)
            {
                if (NtQueryVirtualMemory(h, addr, 0, out mbi, sz, out outLen) != 0) break;
                long rs = (long)mbi.RegionSize.ToUInt64(); if (rs <= 0) break;
                bool readable = mbi.State == MEM_COMMIT && (mbi.Protect & 0x01) == 0 && (mbi.Protect & 0x100) == 0;
                if (readable && rs <= 0x1000000)
                {
                    var buf = new byte[rs]; UIntPtr n;
                    if (NtReadVirtualMemory(h, mbi.BaseAddress, buf, (UIntPtr)rs, out n) == 0)
                    {
                        int i = 0;
                        while (i < buf.Length)
                        {
                            if (IsHexChar(buf[i])) { int j = i; while (j < buf.Length && IsHexChar(buf[j])) j++; if (j - i == 32) { var s = Encoding.ASCII.GetString(buf, i, 32); if (seen.Add(s)) res.Add(s); } i = j; }
                            else i++;
                        }
                    }
                }
                addr = (IntPtr)(mbi.BaseAddress.ToInt64() + rs);
            }
            return res;
        }

        void BtnClean_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Baglan"); return; }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            try { txtModules.Clear(); txtModules.AppendText("Bellekte " + ScanHex32(h).Count + " adet 32'lik hex var.\r\n"); }
            finally { CloseHandle(h); }
        }

        void BtnDiff_Click()
        {
            if (!ProcessAlive()) { MessageBox.Show("Baglan"); return; }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid); if (h == IntPtr.Zero) return;
            try
            {
                var now = ScanHex32(h); txtModules.Clear();
                foreach (var c in candidates) txtModules.AppendText((now.Contains(c) ? "[VAR] " : "[YOK] ") + c + "\r\n");
            }
            finally { CloseHandle(h); }
        }

        void UnhookAll()
        {
            if (!ProcessAlive()) { activeHooks.Clear(); capHooks.Clear(); hookAddr = IntPtr.Zero; return; }
            IntPtr h = OpenProcess(ACCESS_NEEDED, false, (uint)pid);
            if (h != IntPtr.Zero)
            {
                try
                {
                    foreach (var hk in activeHooks)
                    {
                        if (hk.Orig5 != null) WriteMem(h, hk.Target, hk.Orig5);
                        if (hk.Cave != IntPtr.Zero) VirtualFreeEx(h, hk.Cave, UIntPtr.Zero, MEM_RELEASE);
                    }
                }
                finally { CloseHandle(h); }
            }
            activeHooks.Clear(); capHooks.Clear(); hookAddr = IntPtr.Zero;
        }
    }
}