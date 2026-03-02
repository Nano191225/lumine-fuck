// Resolve ambiguities between WPF and Windows Forms types caused by enabling
// UseWindowsForms alongside UseWPF.
global using Application = System.Windows.Application;
global using MessageBox = System.Windows.MessageBox;
global using Color = System.Windows.Media.Color;
global using ColorConverter = System.Windows.Media.ColorConverter;
