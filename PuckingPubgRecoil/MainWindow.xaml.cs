using System;
using System.IO;
using System.Windows;

namespace PuckingPubgRecoil
{
    /// <summary>
    /// MainWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class MainWindow : Window
    {
        //Version
        private string CompileVersion = "1.1";
        private string VersionUrl = "https://raw.githubusercontent.com/nyaong2/PubgWeaponRecoil/main/DeveloperTxt/Version.txt";
        private string GetVersion = null;
        private string VisitorSite = "https://visitor-badge.glitch.me/badge?page_id=PubgWeaponRecoil";        
        public MainWindow()
        {
            #region VersionCheck
            GetVersion = Util.Http.GetTxt(VersionUrl);
            if (GetVersion.Equals("Unknown") || GetVersion.Equals("Null"))
            {
                if (MessageBox.Show("문제 발생으로 최신 버전을 받아올 수 없습니다. \r\n무시하시고 프로그램을 쓰시겠습니까?", "Unknown", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.No)
                {
                    Environment.Exit(0);
                    System.Diagnostics.Process.GetCurrentProcess().Kill();
                    this.Close();
                }
            }
            else if (!CompileVersion.Equals(GetVersion))
            {
                if (MessageBox.Show("프로그램이 구버전입니다. 블로그 글을 확인해주세요 \r\n프로그램을 계속 이용하시겠습니까?", "Unknown", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.No)
                {
                    System.Diagnostics.Process.Start("https://blog.naver.com/vkxld133/222592494145");
                    Environment.Exit(0);
                    System.Diagnostics.Process.GetCurrentProcess().Kill();
                    this.Close();
                }
            }
            Util.Http.Visitor(VisitorSite);
            #endregion

            InitializeComponent();
            TxtBx_Input.Focus();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            //렌더링 된 표지와 동일시 맞추기
            ClearValue(SizeToContentProperty);
            GridMain.ClearValue(WidthProperty);
            GridMain.ClearValue(HeightProperty);

            // 위의 설정으로 인해 프로그램 중앙으로 오지 않는 것 강제로 설정
            this.Left = (System.Windows.SystemParameters.PrimaryScreenWidth / 2) - (this.Width / 2);
            this.Top = (System.Windows.SystemParameters.PrimaryScreenHeight / 2) - (this.Height / 2);
        }

        #region Handler

        #region Resolution
        private void Btn_ResolutionApply(object sender, RoutedEventArgs e)
        {            
            try
            {
                string userAccountName = (System.Security.Principal.WindowsIdentity.GetCurrent().Name).Split('\\')[1];
                string enginePath = @"c:\users\" + userAccountName + @"\Appdata\Local\TslGame\Saved\Config\WindowsNoEditor\Engine.ini";
                string[] readConfigEngine = File.ReadAllLines(enginePath);
                bool susscess = false;

                //읽기전용 체크 후 해제
                FileAttributes fasDisabled = File.GetAttributes(enginePath);
                if ((fasDisabled & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                    File.SetAttributes(enginePath, FileAttributes.Normal);
                

                //해상도부분 찾고 수정
                for (int i = 0; i < readConfigEngine.Length; i++)
                {
                    if (readConfigEngine[i].Contains("r.setres="))
                    {
                        readConfigEngine[i] = "";
                        readConfigEngine[i] = "r.setres=" + TxtBx_Input.Text;
                        susscess = true;
                        break;
                    }
                }

                //해상도부분 못찾은 경우
                if (!susscess)
                {
                    MessageBox.Show("파일 읽기에 실패했습니다.");
                    return;
                }

                //수정된 내용 쓰기.
                using(StreamWriter fileWriter = new StreamWriter(enginePath))
                {
                    foreach(string str in readConfigEngine)
                        fileWriter.WriteLine(str);

                    fileWriter.Close();
                }

                //읽기전용 체크 후 적용
                FileAttributes fasEnabled = File.GetAttributes(enginePath);
                if ((fasEnabled & FileAttributes.ReadOnly) != FileAttributes.ReadOnly)
                    File.SetAttributes(enginePath, FileAttributes.ReadOnly);


                TxtBx_Input.Text = "";
                TxtBx_Input.Focus();
                MessageBox.Show("완료");

            } catch (Exception ex) {
                MessageBox.Show("실패 : " + ex);
            }
        }
        private void Btn_ResolutionUndo(object sender, RoutedEventArgs e)
        {
            string userAccountName = (System.Security.Principal.WindowsIdentity.GetCurrent().Name).Split('\\')[1];
            string enginePath = @"c:\users\" + userAccountName + @"\Appdata\Local\TslGame\Saved\Config\WindowsNoEditor\Engine.ini";

            //읽기전용 체크 후 해제
            FileAttributes fasDisabled = File.GetAttributes(enginePath);
            if ((fasDisabled & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                File.SetAttributes(enginePath, FileAttributes.Normal);

            MessageBox.Show("훈련장 들어갔다 나오시면 복구됩니다.");
        }
        #endregion

        #region MouseDoubleClickSpeed
        private void Btn_MouseSpeedClickSlow(object sender, RoutedEventArgs e)
        {
            Util.Reg.Write(@"HKEY_CURRENT_USER\Control Panel\Mouse", "DoubleClickSpeed", "900", Util.Reg.RegValueKind.SZ);
            MessageBox.Show("완료", "완료", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        private void Btn_MouseSpeedClickFast(object sender, RoutedEventArgs e)
        {
            Util.Reg.Write(@"HKEY_CURRENT_USER\Control Panel\Mouse", "DoubleClickSpeed", "200", Util.Reg.RegValueKind.SZ);
            MessageBox.Show("완료", "완료", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        private void Btn_MouseSpeedClickUndo(object sender, RoutedEventArgs e)
        {
            Util.Reg.Write(@"HKEY_CURRENT_USER\Control Panel\Mouse", "DoubleClickSpeed", "480", Util.Reg.RegValueKind.SZ);
            MessageBox.Show("완료", "완료", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        #endregion

        #region MouseReg
        private void Btn_MouseRegApply(object sender, RoutedEventArgs e)
        {
            if(TxtBx_MouseFlags.Text.Equals("") && TxtBx_MouseMaxSpeed.Text.Equals("") && TxtBx_MouseTimeSpeed.Text.Equals(""))
            {
                MessageBox.Show("값 입력이 안되어있습니다.","Warning",MessageBoxButton.OK,MessageBoxImage.Warning);
                return;
            }
            Util.Reg.Write(@"HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys", "Flags", TxtBx_MouseFlags.Text, Util.Reg.RegValueKind.SZ);
            Util.Reg.Write(@"HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys", "MaximumSpeed", TxtBx_MouseMaxSpeed.Text, Util.Reg.RegValueKind.SZ);
            Util.Reg.Write(@"HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys", "TimeToMaximumSpeed", TxtBx_MouseTimeSpeed.Text, Util.Reg.RegValueKind.SZ);

            MessageBox.Show("완료", "완료", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void Btn_MouseRegUndo(object sender, RoutedEventArgs e)
        {
            TxtBx_MouseFlags.Text = "62";
            TxtBx_MouseMaxSpeed.Text = "80";
            TxtBx_MouseTimeSpeed.Text = "3000";
            
            MessageBox.Show("값을 불러왔습니다. 적용을 눌러주세요.", "완료", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        #endregion

        #endregion //Main
    }
}
