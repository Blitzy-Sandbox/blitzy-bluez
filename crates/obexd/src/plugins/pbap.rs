//! PBAP service driver — stub awaiting full implementation.
//!
//! Provides the types re-exported by the plugins module root.
//! This file will be replaced by the full implementation agent.

/// Phonebook contact data record.
#[derive(Debug, Default, Clone)]
pub struct PhonebookContact {
    /// Full name.
    pub fullname: String,
    /// Family name.
    pub family: String,
    /// Given name.
    pub given: String,
    /// Additional name.
    pub additional: String,
    /// Prefix (e.g. Mr.).
    pub prefix: String,
    /// Suffix (e.g. Jr.).
    pub suffix: String,
    /// Sound/pronunciation field.
    pub sound: String,
    /// Birthday.
    pub birthday: String,
    /// Nickname.
    pub nickname: String,
    /// Website.
    pub website: String,
    /// Photo.
    pub photo: String,
    /// Organization.
    pub company: String,
    /// Department.
    pub department: String,
    /// Title.
    pub title: String,
    /// Role.
    pub role: String,
    /// Email.
    pub email: String,
    /// Formatted address.
    pub address: String,
    /// Telephone.
    pub tel: String,
    /// Categories.
    pub categories: String,
    /// UID.
    pub uid: String,
}

/// Type of telephone number in a phonebook entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhonebookNumberType {
    /// General / unspecified.
    General,
    /// Home number.
    Home,
    /// Mobile number.
    Mobile,
    /// Work / business number.
    Work,
    /// Fax number.
    Fax,
    /// Other.
    Other,
    /// Preferred number.
    Pref,
}

/// Call history type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhonebookCallType {
    /// Incoming call.
    Incoming,
    /// Outgoing call.
    Outgoing,
    /// Missed call.
    Missed,
}

/// PBAP application parameter fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApparamField {
    /// Order.
    Order,
    /// Search value.
    SearchValue,
    /// Search attribute.
    SearchAttribute,
    /// Max list count.
    MaxListCount,
    /// List start offset.
    ListStartOffset,
    /// Filter.
    Filter,
    /// Format.
    Format,
    /// Phonebook size.
    PhonebookSize,
    /// New missed calls.
    NewMissedCalls,
    /// Primary version counter.
    PrimaryVersionCounter,
    /// Secondary version counter.
    SecondaryVersionCounter,
    /// vCard selector.
    VcardSelector,
    /// Database identifier.
    DatabaseIdentifier,
    /// vCard selector operator.
    VcardSelectorOperator,
    /// Reset new missed calls.
    ResetNewMissedCalls,
    /// PBAP supported features.
    PbapSupportedFeatures,
}
