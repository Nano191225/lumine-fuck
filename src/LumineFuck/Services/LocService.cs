using System.Windows;

namespace LumineFuck.Services;

/// <summary>
/// Manages UI language switching between English and Japanese at runtime.
/// </summary>
public static class LocService
{
    private static string _currentLang = "en";

    public static string CurrentLanguage => _currentLang;

    /// <summary>Fired after the language ResourceDictionary has been swapped.</summary>
    public static event Action? LanguageChanged;

    public static void Toggle() => SetLanguage(_currentLang == "en" ? "ja" : "en");

    public static void SetLanguage(string lang)
    {
        _currentLang = lang;

        var merged = Application.Current.Resources.MergedDictionaries;
        var existing = merged.FirstOrDefault(d =>
            d.Source?.OriginalString.Contains("Strings.") == true);
        if (existing != null)
            merged.Remove(existing);

        merged.Add(new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/Resources/Strings.{lang}.xaml")
        });

        LanguageChanged?.Invoke();
    }

    /// <summary>
    /// Gets a localized string from the current Application resources.
    /// Returns the key itself if not found.
    /// </summary>
    public static string Get(string key)
    {
        if (Application.Current.Resources[key] is string s)
            return s;
        return key;
    }
}
