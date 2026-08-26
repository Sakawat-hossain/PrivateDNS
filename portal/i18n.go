package portal

import (
	"net/http"
	"strings"
)

// The portal is bilingual because its audience is.
//
// The customers this product targets are Bangladeshi, many of them working
// abroad, and a meaningful share are far more comfortable reading Bengali than
// English. Both competitors ship Bengali-first interfaces, and it is clearly
// working for them.
//
// Strings live here rather than in the templates so a translator never has to
// touch markup, and so a missing translation falls back visibly rather than
// rendering an empty element.

type Lang string

const (
	LangEN Lang = "en"
	LangBN Lang = "bn"

	langCookie = "pdns_lang"
)

func (l Lang) Valid() bool { return l == LangEN || l == LangBN }

// Dir is the text direction. Both languages here are left-to-right, but the
// templates ask rather than assume.
func (l Lang) Dir() string { return "ltr" }

func (l Lang) Other() Lang {
	if l == LangBN {
		return LangEN
	}
	return LangBN
}

func (l Lang) OtherName() string {
	if l == LangBN {
		return "English"
	}
	return "বাংলা"
}

// T returns the translation for a key, falling back to English and then to the
// key itself. A missing string shows up as its key, which is obvious in review
// rather than silently blank.
func T(l Lang, key string) string {
	if m, ok := strings_[l]; ok {
		if v, ok := m[key]; ok && v != "" {
			return v
		}
	}
	if v, ok := strings_[LangEN][key]; ok {
		return v
	}
	return key
}

// LangFrom resolves the language for a request: an explicit choice in the
// cookie wins, then the browser's preference, then English.
func LangFrom(r *http.Request) Lang {
	if c, err := r.Cookie(langCookie); err == nil {
		if l := Lang(c.Value); l.Valid() {
			return l
		}
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Accept-Language")), "bn") {
		return LangBN
	}
	return LangEN
}

var strings_ = map[Lang]map[string]string{
	LangEN: {
		"app.name":    "PrivateDNS",
		"nav.status":  "Status",
		"nav.setup":   "Setup",
		"nav.check":   "DNS Check",
		"nav.signout": "Sign out",

		"login.title":     "Sign in",
		"login.email":     "Email",
		"login.password":  "Password",
		"login.submit":    "Sign in",
		"login.failed":    "Incorrect email or password.",
		"login.throttled": "Too many attempts. Please wait a few minutes.",

		"status.title":        "Your DNS",
		"status.hostname":     "Your DNS hostname",
		"status.copy":         "Copy",
		"status.copied":       "Copied",
		"status.expires":      "Expires",
		"status.expired":      "Expired",
		"status.active":       "Active",
		"status.suspended":    "Suspended",
		"status.filtering":    "Filtering",
		"status.paused":       "Paused",
		"status.queries":      "Queries",
		"status.blocked":      "Blocked",
		"status.daysleft":     "days left",
		"status.hoursleft":    "hours left",
		"status.expiringsoon": "Your subscription is ending soon.",

		"ip.title":   "Your connection",
		"ip.current": "Current address",
		"ip.update":  "Update my IP",
		"ip.updated": "Address updated",
		"ip.help":    "If the service stops working after you change network, tap this.",
		"ip.explain": "Your internet address changes when you switch between mobile data and Wi-Fi. This tells our servers your new one.",

		"pause.title":   "Pause filtering",
		"pause.button":  "Pause for 5 minutes",
		"pause.active":  "Filtering is paused",
		"pause.help":    "If a website or app is blocked by mistake, pause filtering briefly to reach it.",
		"pause.resumed": "Filtering resumed",

		"setup.title":        "Set up your device",
		"setup.android":      "Android",
		"setup.ios":          "iPhone or iPad",
		"setup.windows":      "Windows",
		"setup.router":       "Router",
		"setup.download":     "Download profile",
		"setup.iosnote":      "Open the downloaded file, then go to Settings to install the profile.",
		"setup.androidsteps": "Settings → Network & internet → Private DNS → Private DNS provider hostname",

		"check.title":    "DNS Check",
		"check.run":      "Check now",
		"check.checking": "Checking…",
		"check.using":    "This device is using PrivateDNS.",
		"check.notusing": "This device is NOT using PrivateDNS.",
		"check.fixtitle": "How to fix it",
		"check.fix1":     "Set Private DNS to your hostname above.",
		"check.fix2":     "Turn off Secure DNS in your browser settings.",
		"check.fix3":     "Check your subscription has not expired.",

		"renew.title":   "Renew",
		"renew.help":    "Contact us to extend your subscription.",
		"error.generic": "Something went wrong. Please try again.",
	},

	LangBN: {
		"app.name":    "প্রাইভেটডিএনএস",
		"nav.status":  "অবস্থা",
		"nav.setup":   "সেটআপ",
		"nav.check":   "ডিএনএস পরীক্ষা",
		"nav.signout": "সাইন আউট",

		"login.title":     "সাইন ইন",
		"login.email":     "ইমেইল",
		"login.password":  "পাসওয়ার্ড",
		"login.submit":    "সাইন ইন করুন",
		"login.failed":    "ইমেইল বা পাসওয়ার্ড ভুল।",
		"login.throttled": "অনেকবার চেষ্টা করা হয়েছে। কয়েক মিনিট পর আবার চেষ্টা করুন।",

		"status.title":        "আপনার ডিএনএস",
		"status.hostname":     "আপনার ডিএনএস হোস্টনেম",
		"status.copy":         "কপি",
		"status.copied":       "কপি হয়েছে",
		"status.expires":      "মেয়াদ শেষ",
		"status.expired":      "মেয়াদ শেষ হয়েছে",
		"status.active":       "সক্রিয়",
		"status.suspended":    "স্থগিত",
		"status.filtering":    "ফিল্টারিং",
		"status.paused":       "বিরতি",
		"status.queries":      "অনুরোধ",
		"status.blocked":      "ব্লক করা",
		"status.daysleft":     "দিন বাকি",
		"status.hoursleft":    "ঘন্টা বাকি",
		"status.expiringsoon": "আপনার সাবস্ক্রিপশনের মেয়াদ শীঘ্রই শেষ হবে।",

		"ip.title":   "আপনার সংযোগ",
		"ip.current": "বর্তমান ঠিকানা",
		"ip.update":  "আমার আইপি আপডেট করুন",
		"ip.updated": "ঠিকানা আপডেট হয়েছে",
		"ip.help":    "নেটওয়ার্ক পরিবর্তনের পর সার্ভিস বন্ধ হলে এখানে চাপুন।",
		"ip.explain": "মোবাইল ডেটা ও ওয়াই-ফাই পরিবর্তন করলে আপনার ইন্টারনেট ঠিকানা বদলে যায়। এটি আমাদের সার্ভারকে নতুন ঠিকানা জানায়।",

		"pause.title":   "ফিল্টারিং বিরতি",
		"pause.button":  "৫ মিনিটের জন্য বিরতি",
		"pause.active":  "ফিল্টারিং বিরতিতে আছে",
		"pause.help":    "কোনো ওয়েবসাইট বা অ্যাপ ভুলবশত ব্লক হলে অল্প সময়ের জন্য ফিল্টারিং বন্ধ করুন।",
		"pause.resumed": "ফিল্টারিং আবার চালু হয়েছে",

		"setup.title":        "আপনার ডিভাইস সেটআপ করুন",
		"setup.android":      "অ্যান্ড্রয়েড",
		"setup.ios":          "আইফোন বা আইপ্যাড",
		"setup.windows":      "উইন্ডোজ",
		"setup.router":       "রাউটার",
		"setup.download":     "প্রোফাইল ডাউনলোড করুন",
		"setup.iosnote":      "ডাউনলোড করা ফাইলটি খুলুন, তারপর Settings-এ গিয়ে প্রোফাইল ইনস্টল করুন।",
		"setup.androidsteps": "Settings → Network & internet → Private DNS → Private DNS provider hostname",

		"check.title":    "ডিএনএস পরীক্ষা",
		"check.run":      "এখনই পরীক্ষা করুন",
		"check.checking": "পরীক্ষা চলছে…",
		"check.using":    "এই ডিভাইসটি প্রাইভেটডিএনএস ব্যবহার করছে।",
		"check.notusing": "এই ডিভাইসটি প্রাইভেটডিএনএস ব্যবহার করছে না।",
		"check.fixtitle": "যেভাবে ঠিক করবেন",
		"check.fix1":     "উপরের হোস্টনেমটি Private DNS হিসেবে সেট করুন।",
		"check.fix2":     "ব্রাউজারের Secure DNS বন্ধ করুন।",
		"check.fix3":     "আপনার সাবস্ক্রিপশনের মেয়াদ আছে কিনা দেখুন।",

		"renew.title":   "নবায়ন",
		"renew.help":    "সাবস্ক্রিপশন বাড়াতে আমাদের সাথে যোগাযোগ করুন।",
		"error.generic": "কিছু ভুল হয়েছে। আবার চেষ্টা করুন।",
	},
}
