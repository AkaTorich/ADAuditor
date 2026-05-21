using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using ADAuditor.Core;
using ADAuditor.Report;

namespace ADAuditor
{
    public partial class MainWindow : Window
    {
        private readonly ObservableCollection<FindingRow> _rows = new ObservableCollection<FindingRow>();
        private AuditReport _report;

        public MainWindow()
        {
            InitializeComponent();
            GridFindings.ItemsSource = _rows;
            WinChrome.HookMaxFix(this);
        }

        private void BtnMin_Click(object sender, RoutedEventArgs e)
            => WindowState = WindowState.Minimized;

        private void BtnMax_Click(object sender, RoutedEventArgs e)
            => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

        private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();

        private void Window_StateChanged(object sender, EventArgs e)
        {
            if (WindowState == WindowState.Maximized)
            {
                RootBorder.BorderThickness = new Thickness(0);
                BtnMax.Content = "❐"; // restore glyph
            }
            else
            {
                RootBorder.BorderThickness = new Thickness(1);
                BtnMax.Content = "□"; // maximize glyph
            }
        }


        private void Log(string line)
        {
            Dispatcher.Invoke(() =>
            {
                TxtLog.AppendText(line + Environment.NewLine);
                TxtLog.ScrollToEnd();
            });
        }

        private void SetStatus(string s) => Dispatcher.Invoke(() => TxtStatus.Text = "STATUS: " + s);

        private async void BtnRun_Click(object sender, RoutedEventArgs e)
        {
            BtnRun.IsEnabled = false;
            BtnExport.IsEnabled = false;
            _rows.Clear();
            ScorePanel.Items.Clear();
            TxtLog.Clear();
            TxtDetails.Text = "// running ...";
            _report = null;

            string domain = TxtServer.Text?.Trim();
            string ip = TxtIp.Text?.Trim();
            NetworkCredential cred = BuildCredential(TxtUser.Text, TxtPass.Password);

            // Connect by IP when provided (DNS-independent); otherwise by domain/DC name.
            string connectHost = !string.IsNullOrEmpty(ip) ? ip : domain;

            SetStatus("connecting to " + (string.IsNullOrEmpty(connectHost) ? "current domain" : connectHost) + " ...");
            Log("[*] AD_AUDITOR session start " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            if (!string.IsNullOrEmpty(ip))
                Log("[*] Connecting directly to DC IP " + ip +
                    (string.IsNullOrEmpty(domain) ? "" : " (domain: " + domain + ")"));

            try
            {
                var report = await Task.Run(() =>
                {
                    using (var ctx = new AuditContext(connectHost, cred))
                    {
                        ctx.Log = Log;
                        ctx.Connect();
                        return new AuditEngine().Run(ctx);
                    }
                });

                _report = report;
                PopulateResults(report);
                BtnExport.IsEnabled = true;
                BtnExportCsv.IsEnabled = true;
                BtnGraph.IsEnabled = report.AttackGraph != null && report.AttackGraph.Nodes.Count > 0;
                SetStatus("done. " + report.Findings.Count + " findings, global score " + report.GlobalScore() + "/100.");
            }
            catch (Exception ex)
            {
                Log("[!] FATAL: " + ex.Message);
                SetStatus("error - " + ex.Message);
                MessageBox.Show(ex.Message, "Audit failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnRun.IsEnabled = true;
            }
        }

        private void PopulateResults(AuditReport report)
        {
            foreach (var f in report.Findings)
                _rows.Add(new FindingRow(f));

            // score strip
            AddScore("GLOBAL", report.GlobalScore());
            foreach (Category c in Enum.GetValues(typeof(Category)))
                AddScore(c.ToString().ToUpper(), report.Score(c));
        }

        private void AddScore(string label, int score)
        {
            var color = score >= 75 ? Color.FromRgb(0xFF, 0x3B, 0x30)
                      : score >= 50 ? Color.FromRgb(0xFF, 0x8C, 0x00)
                      : score >= 25 ? Color.FromRgb(0xFF, 0xB0, 0x00)
                                    : Color.FromRgb(0x33, 0xFF, 0x66);
            var border = new Border
            {
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x1E, 0x8F, 0x3E)),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(14, 6, 14, 6),
                Margin = new Thickness(0, 0, 8, 0),
                MinWidth = 120
            };
            var sp = new StackPanel();
            sp.Children.Add(new TextBlock
            {
                Text = label,
                Foreground = new SolidColorBrush(Color.FromRgb(0x1E, 0x8F, 0x3E)),
                FontSize = 11,
                HorizontalAlignment = HorizontalAlignment.Center
            });
            sp.Children.Add(new TextBlock
            {
                Text = score.ToString(),
                Foreground = new SolidColorBrush(color),
                FontSize = 26,
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center
            });
            border.Child = sp;
            ScorePanel.Items.Add(border);
        }

        private void GridFindings_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (GridFindings.SelectedItem is FindingRow row)
            {
                var f = row.Model;
                var sb = new System.Text.StringBuilder();
                sb.AppendLine("[" + f.Id + "] " + f.Title);
                sb.AppendLine("severity: " + f.Severity + "   points: " + f.Points);
                if (!string.IsNullOrEmpty(f.Rationale)) sb.AppendLine().AppendLine("WHY: " + f.Rationale);
                if (!string.IsNullOrEmpty(f.Recommendation)) sb.AppendLine().AppendLine("FIX: " + f.Recommendation);
                if (f.Details.Count > 0)
                {
                    sb.AppendLine().AppendLine("AFFECTED (" + f.Details.Count + "):");
                    foreach (var d in f.Details) sb.AppendLine("  - " + d);
                }
                TxtDetails.Text = sb.ToString();
            }
        }

        private void BtnExport_Click(object sender, RoutedEventArgs e)
        {
            if (_report == null) return;
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                FileName = "ADAudit_" + (_report.DomainName ?? "domain") + "_" +
                           DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".html",
                Filter = "HTML report (*.html)|*.html"
            };
            if (dlg.ShowDialog() != true) return;
            try
            {
                System.IO.File.WriteAllText(dlg.FileName, HtmlReportWriter.Build(_report));
                SetStatus("report written: " + dlg.FileName);
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnExportCsv_Click(object sender, RoutedEventArgs e)
        {
            if (_report == null) return;
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                FileName = "ADAudit_" + (_report.DomainName ?? "domain") + "_" +
                           DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".csv",
                Filter = "CSV (*.csv)|*.csv"
            };
            if (dlg.ShowDialog() != true) return;
            try
            {
                // UTF-8 with BOM so Excel reads non-ASCII correctly.
                System.IO.File.WriteAllText(dlg.FileName, CsvReportWriter.Build(_report), new System.Text.UTF8Encoding(true));
                SetStatus("CSV written: " + dlg.FileName);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnGraph_Click(object sender, RoutedEventArgs e)
        {
            if (_report?.AttackGraph == null || _report.AttackGraph.Nodes.Count == 0)
            {
                MessageBox.Show("No attack paths were found to visualize.", "Attack Path Graph",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            new GraphWindow(_report.AttackGraph) { Owner = this }.Show();
        }

        private static NetworkCredential BuildCredential(string user, string pass)
        {
            if (string.IsNullOrWhiteSpace(user)) return null;
            user = user.Trim();
            int slash = user.IndexOf('\\');
            if (slash > 0)
                return new NetworkCredential(user.Substring(slash + 1), pass, user.Substring(0, slash));
            return new NetworkCredential(user, pass);
        }
    }

    // Grid row wrapper
    public sealed class FindingRow
    {
        public Finding Model { get; }
        public FindingRow(Finding f) { Model = f; }
        public string Sev => Model.Severity.ToString().ToUpper();
        public Severity Severity => Model.Severity;
        public string Cat => Model.Category.ToString();
        public string Id => Model.Id;
        public string Title => Model.Title;
        public int Count => Model.Details.Count;
    }

    // Color the severity cell
    public sealed class SeverityToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var s = value is Severity sev ? sev : Severity.Info;
            switch (s)
            {
                case Severity.Critical: return new SolidColorBrush(Color.FromRgb(0xFF, 0x3B, 0x30));
                case Severity.High: return new SolidColorBrush(Color.FromRgb(0xFF, 0x8C, 0x00));
                case Severity.Medium: return new SolidColorBrush(Color.FromRgb(0xFF, 0xB0, 0x00));
                case Severity.Low: return new SolidColorBrush(Color.FromRgb(0x7C, 0xFC, 0x00));
                default: return new SolidColorBrush(Color.FromRgb(0x1E, 0x8F, 0x3E));
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
