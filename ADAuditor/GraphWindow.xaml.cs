using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using ADAuditor.Core;
using ADAuditor.Report;

namespace ADAuditor
{
    public partial class GraphWindow : Window
    {
        private const double ColSpacing = 250;
        private const double RowSpacing = 50;
        private const double NodeW = 190;
        private const double NodeH = 30;
        private const double Pad = 40;

        private static readonly Brush TargetBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0x3B, 0x30));
        private static readonly Brush BroadBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0x8C, 0x00));
        private static readonly Brush SourceBrush = new SolidColorBrush(Color.FromRgb(0x33, 0xFF, 0x66));
        private static readonly Brush MidBrush = new SolidColorBrush(Color.FromRgb(0x1E, 0x8F, 0x3E));
        private static readonly Brush MemberEdge = new SolidColorBrush(Color.FromRgb(0x2E, 0x6F, 0x42));
        private static readonly Brush ControlEdge = new SolidColorBrush(Color.FromRgb(0xFF, 0xB0, 0x00));
        private static readonly Brush WeakEdge = new SolidColorBrush(Color.FromRgb(0xFF, 0x3B, 0x30));
        private static readonly Brush Ink = new SolidColorBrush(Color.FromRgb(0x05, 0x08, 0x05));

        private bool _dragging;
        private Point _dragStart;
        private double _panStartX, _panStartY;
        private GraphModel _graph;

        public GraphWindow(GraphModel graph)
        {
            InitializeComponent();
            WinChrome.HookMaxFix(this);
            _graph = graph;
            Render(graph);
        }

        private void BtnDot_Click(object sender, RoutedEventArgs e)
        {
            if (_graph == null) return;
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                FileName = "ADAudit_attackpaths_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".dot",
                Filter = "Graphviz DOT (*.dot)|*.dot"
            };
            if (dlg.ShowDialog() != true) return;
            try { System.IO.File.WriteAllText(dlg.FileName, DotGraphWriter.Build(_graph)); }
            catch (Exception ex) { MessageBox.Show(ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Error); }
        }

        // ---- title bar ----
        private void BtnMin_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void BtnMax_Click(object sender, RoutedEventArgs e)
            => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();

        private void Window_StateChanged(object sender, EventArgs e)
        {
            if (WindowState == WindowState.Maximized)
            {
                RootBorder.BorderThickness = new Thickness(0);
                BtnMax.Content = "❐";
            }
            else
            {
                RootBorder.BorderThickness = new Thickness(1);
                BtnMax.Content = "□";
            }
        }

        // ---- pan / zoom ----
        private void Viewport_MouseWheel(object sender, MouseWheelEventArgs e)
        {
            Point m = e.GetPosition(Viewport);
            double s0 = Zoom.ScaleX;
            double f = e.Delta > 0 ? 1.12 : 1 / 1.12;
            double s1 = Math.Max(0.15, Math.Min(4.0, s0 * f));
            // keep the canvas point under the cursor fixed
            Panr.X = m.X - (m.X - Panr.X) * (s1 / s0);
            Panr.Y = m.Y - (m.Y - Panr.Y) * (s1 / s0);
            Zoom.ScaleX = s1;
            Zoom.ScaleY = s1;
            e.Handled = true;
        }

        private void Viewport_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2) { ResetView(); return; }
            _dragging = true;
            _dragStart = e.GetPosition(Viewport);
            _panStartX = Panr.X;
            _panStartY = Panr.Y;
            Viewport.CaptureMouse();
            Viewport.Cursor = Cursors.ScrollAll;
        }

        private void Viewport_MouseMove(object sender, MouseEventArgs e)
        {
            if (!_dragging) return;
            Point p = e.GetPosition(Viewport);
            Panr.X = _panStartX + (p.X - _dragStart.X);
            Panr.Y = _panStartY + (p.Y - _dragStart.Y);
        }

        private void Viewport_MouseUp(object sender, MouseButtonEventArgs e)
        {
            _dragging = false;
            Viewport.ReleaseMouseCapture();
            Viewport.Cursor = Cursors.Arrow;
        }

        private void Viewport_Reset(object sender, MouseButtonEventArgs e) => ResetView();

        private void ResetView()
        {
            Zoom.ScaleX = Zoom.ScaleY = 1;
            Panr.X = Panr.Y = 0;
        }

        // ---- rendering ----
        private void Render(GraphModel g)
        {
            if (g == null || g.Nodes.Count == 0)
            {
                TxtInfo.Text = "no attack paths to render";
                return;
            }

            int maxDist = 0;
            foreach (var n in g.Nodes) if (n.Distance > maxDist) maxDist = n.Distance;

            var byDist = new Dictionary<int, List<GraphNode>>();
            foreach (var n in g.Nodes)
            {
                if (!byDist.TryGetValue(n.Distance, out var l)) { l = new List<GraphNode>(); byDist[n.Distance] = l; }
                l.Add(n);
            }

            var pos = new Dictionary<string, Point>(StringComparer.OrdinalIgnoreCase);
            int maxRows = 0;
            foreach (var kv in byDist)
            {
                int col = maxDist - kv.Key;
                var nodes = kv.Value;
                nodes.Sort((a, b) => string.Compare(a.Label, b.Label, StringComparison.OrdinalIgnoreCase));
                for (int i = 0; i < nodes.Count; i++)
                    pos[nodes[i].Id] = new Point(Pad + col * ColSpacing, Pad + i * RowSpacing);
                if (nodes.Count > maxRows) maxRows = nodes.Count;
            }

            Cv.Width = Pad * 2 + maxDist * ColSpacing + NodeW;
            Cv.Height = Pad * 2 + maxRows * RowSpacing;

            foreach (var e in g.Edges)
                if (pos.TryGetValue(e.From, out var pf) && pos.TryGetValue(e.To, out var pt))
                    DrawEdge(pf, pt, e.Type, e.Weak);

            foreach (var n in g.Nodes)
                if (pos.TryGetValue(n.Id, out var p))
                    DrawNode(n, p);

            TxtInfo.Text = g.Nodes.Count + " nodes, " + g.Edges.Count + " edges";
        }

        private void DrawNode(GraphNode n, Point p)
        {
            Brush b;
            switch (n.Kind)
            {
                case "target": b = TargetBrush; break;
                case "broad": b = BroadBrush; break;
                case "source": b = SourceBrush; break;
                default: b = MidBrush; break;
            }

            var border = new Border
            {
                Width = NodeW,
                Height = NodeH,
                Background = new SolidColorBrush(Color.FromRgb(0x0A, 0x14, 0x10)),
                BorderBrush = b,
                BorderThickness = new Thickness(n.Kind == "target" || n.Kind == "broad" ? 2 : 1),
                CornerRadius = new CornerRadius(3),
                ToolTip = n.Label + "  [" + n.Kind + ", " + n.Distance + " hops to tier-0]"
            };
            border.Child = new TextBlock
            {
                Text = n.Label,
                Foreground = b,
                FontFamily = (FontFamily)Application.Current.Resources["MonoFont"],
                FontSize = 12,
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(6, 0, 6, 0)
            };
            Canvas.SetLeft(border, p.X);
            Canvas.SetTop(border, p.Y);
            Cv.Children.Add(border);
        }

        private void DrawEdge(Point from, Point to, string type, bool weak)
        {
            bool member = type == "MemberOf";
            Brush stroke = weak ? WeakEdge : (member ? MemberEdge : ControlEdge);

            double x1 = from.X + NodeW, y1 = from.Y + NodeH / 2;
            double x2 = to.X, y2 = to.Y + NodeH / 2;

            Cv.Children.Add(new Line
            {
                X1 = x1,
                Y1 = y1,
                X2 = x2,
                Y2 = y2,
                Stroke = stroke,
                StrokeThickness = weak ? 2.8 : (member ? 1 : 1.6)
            });

            double ang = Math.Atan2(y2 - y1, x2 - x1);
            const double sz = 9;
            var tip = new Point(x2, y2);
            var b1 = new Point(x2 - sz * Math.Cos(ang - 0.4), y2 - sz * Math.Sin(ang - 0.4));
            var b2 = new Point(x2 - sz * Math.Cos(ang + 0.4), y2 - sz * Math.Sin(ang + 0.4));
            Cv.Children.Add(new Polygon { Points = new PointCollection { tip, b1, b2 }, Fill = stroke });

            var label = new TextBlock
            {
                Text = type,
                Foreground = stroke,
                Background = Ink,
                FontFamily = (FontFamily)Application.Current.Resources["MonoFont"],
                FontSize = 10,
                Padding = new Thickness(2, 0, 2, 0)
            };
            Canvas.SetLeft(label, (x1 + x2) / 2 - type.Length * 3);
            Canvas.SetTop(label, (y1 + y2) / 2 - 9);
            Cv.Children.Add(label);
        }
    }
}
