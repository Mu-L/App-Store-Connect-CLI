package appleads

import "strings"

// platformReportsOptimizationEndpointSpecs returns the Platform API v1
// reporting, insights, recommendations, suggestions, and change-history
// surface. Reporting request pagination remains in the JSON body, so these
// commands deliberately preserve Apple's raw response envelopes instead of
// exposing the query-string --paginate behavior used by legacy endpoints.
func platformReportsOptimizationEndpointSpecs() []EndpointSpec {
	platform := func(name, path string, commandPath []string, bodyKind BodyKind, bodyType, responseType string, requiresConfirm bool) EndpointSpec {
		return EndpointSpec{
			Name:            name,
			Method:          "POST",
			Path:            path,
			Version:         APIVersionPlatformV1,
			Context:         ContextAdAccount,
			CommandPath:     append([]string(nil), commandPath...),
			BodyKind:        bodyKind,
			BodyType:        bodyType,
			ResponseType:    responseType,
			RequiresConfirm: requiresConfirm,
			RetrySafe:       strings.HasSuffix(path, "/query"),
		}
	}

	specs := []EndpointSpec{
		platform("platform-get-app-ad-group-reports", "v1/reports/apps/adgroups/query", []string{"reports", "apps", "ad-groups"}, BodyObject, "AppsReportingRequest", "AppsAdGroupReportResponse", false),
		platform("platform-get-app-ad-reports", "v1/reports/apps/ads/query", []string{"reports", "apps", "ads"}, BodyObject, "AppsReportingRequest", "AppsAdReportResponse", false),
		platform("platform-get-app-campaign-reports", "v1/reports/apps/campaigns/query", []string{"reports", "apps", "campaigns"}, BodyObject, "AppsReportingRequest", "AppsCampaignReportResponse", false),
		platform("platform-get-app-keyword-reports", "v1/reports/apps/keywords/query", []string{"reports", "apps", "keywords"}, BodyObject, "AppsReportingRequest", "AppsKeywordReportResponse", false),
		platform("platform-get-app-search-term-reports", "v1/reports/apps/searchterms/query", []string{"reports", "apps", "search-terms"}, BodyObject, "AppsReportingRequest", "AppsSearchTermReportResponse", false),

		platform("platform-get-brand-ad-group-reports", "v1/reports/business-brands/adgroups/query", []string{"reports", "brands", "ad-groups"}, BodyObject, "BrandsReportingRequest", "BrandsAdGroupReportResponse", false),
		platform("platform-get-brand-ad-reports", "v1/reports/business-brands/ads/query", []string{"reports", "brands", "ads"}, BodyObject, "BrandsReportingRequest", "BrandsAdReportResponse", false),
		platform("platform-get-brand-campaign-reports", "v1/reports/business-brands/campaigns/query", []string{"reports", "brands", "campaigns"}, BodyObject, "BrandsReportingRequest", "BrandsCampaignReportResponse", false),
		platform("platform-get-brand-keyword-reports", "v1/reports/business-brands/keywords/query", []string{"reports", "brands", "keywords"}, BodyObject, "BrandsReportingRequest", "BrandsKeywordReportResponse", false),
		platform("platform-get-brand-search-term-reports", "v1/reports/business-brands/searchterms/query", []string{"reports", "brands", "search-terms"}, BodyObject, "BrandsReportingRequest", "BrandsSearchTermReportResponse", false),

		platform("platform-query-app-impression-share-data", "v1/insights/apps/impression-share/query", []string{"insights", "impression-share", "find"}, BodyObject, "ImpressionShareQueryRequest", "ImpressionShareQueryResponse", false),
		platform("platform-query-app-search-term-popularity-data", "v1/insights/apps/search-term-popularity/query", []string{"insights", "search-term-popularity", "find"}, BodyObject, "SearchTermPopularityQueryRequest", "SearchTermPopularityQueryResponse", false),

		platform("platform-apply-daily-budget-recommendations", "v1/recommendations/daily-budgets/apply", []string{"recommendations", "daily-budgets", "apply"}, BodyArray, "[ApplyDailyCapRecommendation]", "RecommendationApplyDailyBudgetResponse", true),
		platform("platform-dismiss-daily-budget-recommendations", "v1/recommendations/daily-budgets/dismiss", []string{"recommendations", "daily-budgets", "dismiss"}, BodyArray, "[ApplyDailyCapRecommendation]", "RecommendationDismissDailyBudgetResponse", true),
		platform("platform-query-daily-budget-recommendations", "v1/recommendations/daily-budgets/query", []string{"recommendations", "daily-budgets", "find"}, BodyObject, "RecommendationQueryRequest", "RecommendationQueryDailyBudgetResponse", false),
		platform("platform-apply-target-cpa-recommendations", "v1/recommendations/target-cpas/apply", []string{"recommendations", "target-cpas", "apply"}, BodyArray, "[ApplyTargetCpaRecommendation]", "RecommendationApplyTargetCpaResponse", true),
		platform("platform-dismiss-target-cpa-recommendations", "v1/recommendations/target-cpas/dismiss", []string{"recommendations", "target-cpas", "dismiss"}, BodyArray, "[ApplyTargetCpaRecommendation]", "RecommendationDismissTargetCpaResponse", true),
		platform("platform-query-target-cpa-recommendations", "v1/recommendations/target-cpas/query", []string{"recommendations", "target-cpas", "find"}, BodyObject, "RecommendationQueryRequest", "RecommendationQueryTargetCpaResponse", false),

		platform("platform-query-category-suggestions", "v1/suggestions/categories/query", []string{"suggestions", "categories", "find"}, BodyObject, "RecommendationQueryRequest", "RecommendationQueryCategorySuggestionResponse", false),
		platform("platform-query-keyword-suggestions", "v1/suggestions/keywords/query", []string{"suggestions", "keywords", "find"}, BodyObject, "RecommendationQueryRequest", "RecommendationQueryKeywordSuggestionResponse", false),
		platform("platform-query-phrase-suggestions", "v1/suggestions/phrases/query", []string{"suggestions", "phrases", "find"}, BodyObject, "RecommendationQueryRequest", "RecommendationQueryPhraseSuggestionResponse", false),
		platform("platform-query-target-cpa-suggestion", "v1/suggestions/target-cpas/query", []string{"suggestions", "target-cpas", "find"}, BodyObject, "RecommendationQueryRequest", "RecommendationQueryTargetCpaSuggestionResponse", false),

		platform("platform-query-change-history", "v1/change-history/query", []string{"change-history", "find"}, BodyObject, "AuditQuery", "AuditSummaryResponse", false),
	}

	for index := range specs {
		spec := &specs[index]
		switch {
		case strings.HasPrefix(spec.Path, "v1/reports/"):
			spec.BodyFileExample = "report.json"
			spec.BodyHint = "Use nested timeRange {start,end,timeZone,granularity}; pagination is {offset,pageSize}. Put campaign and ad-group selectors in filters. EMPTY_METRICS cannot be combined with groupBy; brand reports support only GRAND_TOTAL."
		case spec.Name == "platform-query-app-impression-share-data":
			spec.BodyFileExample = "query.json"
			spec.BodyHint = "Required: filters must include promotedObjectId, plus a complete timeRange. Use UTC and DAILY (maximum 30 days) or WEEKLY_SUN_SAT (maximum 4 weeks, starting Sunday). impressionShareReportType is FIRST_SLOT or ALL_SLOTS; pageSize max 5000; at most 2 sort fields."
		case spec.Name == "platform-query-app-search-term-popularity-data":
			spec.BodyFileExample = "query.json"
			spec.BodyHint = "Required: timeRange. Use UTC and WEEKLY_SUN_SAT or MONTHLY; pageSize max 5000; at most 2 sort fields."
		case strings.HasPrefix(spec.Path, "v1/suggestions/categories/") || strings.HasPrefix(spec.Path, "v1/suggestions/phrases/"):
			spec.BodyFileExample = "query.json"
			spec.BodyHint = "For queryType SUGGESTION, filter by promotedObjectId and promotedObjectType. For queryType SEARCH, use the phrase or category filter documented by Apple; Apple's generic request schema does not describe this exception."
		case strings.HasPrefix(spec.Path, "v1/suggestions/") || (strings.HasPrefix(spec.Path, "v1/recommendations/") && strings.HasSuffix(spec.Path, "/query")):
			spec.BodyFileExample = "query.json"
			spec.BodyHint = "filters must include promotedObjectId and promotedObjectType. Pagination defaults to offset 0 and pageSize 20, with pageSize max 1000."
		case spec.RequiresConfirm:
			spec.BodyFileExample = "recommendations.json"
			spec.BodyHint = "Pass a non-empty array built from a recommendation query response. Apply and dismiss operations require --confirm."
		case spec.BodyKind != BodyNone:
			spec.BodyFileExample = "query.json"
		}
	}

	specs = append(specs, EndpointSpec{
		Name:         "platform-get-change-history-detail",
		Method:       "GET",
		Path:         "v1/change-history/{detailId}",
		Version:      APIVersionPlatformV1,
		Context:      ContextAdAccount,
		CommandPath:  []string{"change-history", "view"},
		ResponseType: "ChangeDetailsResponse",
		PathParams: []ParamSpec{
			{Name: "detailId", Flag: "detail-id", Type: ParamString, Required: true},
		},
		QueryParams: []ParamSpec{
			{Name: "limit", Flag: "limit", Type: ParamInt},
			{Name: "offset", Flag: "offset", Type: ParamInt},
		},
	})
	return specs
}
