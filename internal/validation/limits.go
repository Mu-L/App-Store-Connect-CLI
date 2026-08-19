package validation

// App Store metadata character limits.
const (
	LimitDescription     = 4000
	LimitKeywords        = 100
	LimitWhatsNew        = 4000
	LimitPromotionalText = 170
	LimitName            = 30
	LimitSubtitle        = 30
)

// LimitScreenshotsPerSet is the maximum number of screenshots the App Store
// accepts in a single screenshot set, meaning one display type within one
// localization. The App Store Connect OpenAPI snapshot does not express this
// cap, so it is enforced server-side at upload time.
const LimitScreenshotsPerSet = 10
