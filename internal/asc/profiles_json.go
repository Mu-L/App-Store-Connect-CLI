package asc

import "encoding/json"

// UnmarshalJSON records that the profile attributes member was present while
// retaining the existing value-shaped ProfileAttributes API.
func (a *ProfileAttributes) UnmarshalJSON(data []byte) error {
	type profileAttributes ProfileAttributes
	var decoded profileAttributes
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*a = ProfileAttributes(decoded)
	a.attributesPresent = true
	return nil
}

// GetLinks returns the links field for pagination.
func (r *ProfilesResponse) GetLinks() *Links {
	return &r.Links
}

// GetMeta returns the raw metadata field.
func (r *ProfilesResponse) GetMeta() json.RawMessage {
	return r.Meta
}

// GetData returns the data field for aggregation.
func (r *ProfilesResponse) GetData() any {
	return r.Data
}

// MarshalJSON omits attributes when Apple omitted them from a relationship-only
// sparse profile resource, while preserving the existing response envelope.
func (r ProfilesResponse) MarshalJSON() ([]byte, error) {
	type profileResource struct {
		Type          ResourceType       `json:"type"`
		ID            string             `json:"id"`
		Attributes    *ProfileAttributes `json:"attributes,omitempty"`
		Relationships json.RawMessage    `json:"relationships,omitempty"`
		Links         json.RawMessage    `json:"links,omitempty"`
	}
	var data []profileResource
	if r.Data != nil {
		data = make([]profileResource, len(r.Data))
	}
	for i, resource := range r.Data {
		data[i] = profileResource{
			Type:          resource.Type,
			ID:            resource.ID,
			Relationships: resource.Relationships,
			Links:         resource.Links,
		}
		if profileAttributesHaveValues(resource.Attributes) {
			attributes := resource.Attributes
			data[i].Attributes = &attributes
		}
	}

	type profilesResponse struct {
		Data     []profileResource `json:"data"`
		Links    Links             `json:"links"`
		Included json.RawMessage   `json:"included,omitempty"`
		Meta     json.RawMessage   `json:"meta,omitempty"`
	}
	return json.Marshal(profilesResponse{
		Data:     data,
		Links:    r.Links,
		Included: r.Included,
		Meta:     r.Meta,
	})
}

func profileAttributesHaveValues(attributes ProfileAttributes) bool {
	return attributes.attributesPresent ||
		attributes.Name != "" ||
		attributes.Platform != "" ||
		attributes.ProfileType != "" ||
		attributes.ProfileState != "" ||
		attributes.ProfileContent != "" ||
		attributes.UUID != "" ||
		attributes.CreatedDate != "" ||
		attributes.ExpirationDate != ""
}
