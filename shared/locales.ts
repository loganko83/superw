export interface LocaleConfig {
  code: string;
  name: string;
  nativeName: string;
  flag: string;
  country: string;
  countryCode: string;
  rtl?: boolean;
}

export const supportedLocales: LocaleConfig[] = [
  { code: 'ko', name: 'Korean', nativeName: '한국어', flag: '🇰🇷', country: 'South Korea', countryCode: 'KR' },
  { code: 'en', name: 'English', nativeName: 'English', flag: '🇺🇸', country: 'United States', countryCode: 'US' },
  { code: 'ja', name: 'Japanese', nativeName: '日本語', flag: '🇯🇵', country: 'Japan', countryCode: 'JP' },
  { code: 'zh-CN', name: 'Chinese (Simplified)', nativeName: '简体中文', flag: '🇨🇳', country: 'China', countryCode: 'CN' },
  { code: 'zh-TW', name: 'Chinese (Traditional)', nativeName: '繁體中文', flag: '🇹🇼', country: 'Taiwan', countryCode: 'TW' },
  { code: 'es', name: 'Spanish', nativeName: 'Español', flag: '🇪🇸', country: 'Spain', countryCode: 'ES' },
  { code: 'fr', name: 'French', nativeName: 'Français', flag: '🇫🇷', country: 'France', countryCode: 'FR' },
  { code: 'de', name: 'German', nativeName: 'Deutsch', flag: '🇩🇪', country: 'Germany', countryCode: 'DE' },
  { code: 'pt', name: 'Portuguese', nativeName: 'Português', flag: '🇧🇷', country: 'Brazil', countryCode: 'BR' },
  { code: 'ru', name: 'Russian', nativeName: 'Русский', flag: '🇷🇺', country: 'Russia', countryCode: 'RU' },
  { code: 'ar', name: 'Arabic', nativeName: 'العربية', flag: '🇸🇦', country: 'Saudi Arabia', countryCode: 'SA', rtl: true },
  { code: 'hi', name: 'Hindi', nativeName: 'हिन्दी', flag: '🇮🇳', country: 'India', countryCode: 'IN' },
  { code: 'th', name: 'Thai', nativeName: 'ไทย', flag: '🇹🇭', country: 'Thailand', countryCode: 'TH' },
  { code: 'vi', name: 'Vietnamese', nativeName: 'Tiếng Việt', flag: '🇻🇳', country: 'Vietnam', countryCode: 'VN' },
  { code: 'id', name: 'Indonesian', nativeName: 'Bahasa Indonesia', flag: '🇮🇩', country: 'Indonesia', countryCode: 'ID' },
  { code: 'ms', name: 'Malay', nativeName: 'Bahasa Melayu', flag: '🇲🇾', country: 'Malaysia', countryCode: 'MY' },
  { code: 'tl', name: 'Filipino', nativeName: 'Filipino', flag: '🇵🇭', country: 'Philippines', countryCode: 'PH' },
];

export const defaultLocale = 'ko';

export function getLocaleByCode(code: string): LocaleConfig | undefined {
  return supportedLocales.find(locale => locale.code === code);
}

export function getLocaleByCountryCode(countryCode: string): LocaleConfig | undefined {
  return supportedLocales.find(locale => locale.countryCode === countryCode);
}