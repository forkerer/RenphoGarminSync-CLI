﻿using System;
using System.Text.Json.Serialization;

namespace RenphoGarminSync.Garmin.Shared.Models.Responses
{

    public class UserProfileResponse
    {
        [JsonPropertyName("id")]
        public int? Id { get; set; }

        [JsonPropertyName("profileId")]
        public int? ProfileId { get; set; }

        [JsonPropertyName("garminGUID")]
        public string GarminGUID { get; set; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; set; }

        [JsonPropertyName("fullName")]
        public string FullName { get; set; }

        [JsonPropertyName("userName")]
        public string UserName { get; set; }

        [JsonPropertyName("profileImageType")]
        public string ProfileImageType { get; set; }

        [JsonPropertyName("profileImageUrlLarge")]
        public string ProfileImageUrlLarge { get; set; }

        [JsonPropertyName("profileImageUrlMedium")]
        public string ProfileImageUrlMedium { get; set; }

        [JsonPropertyName("profileImageUrlSmall")]
        public string ProfileImageUrlSmall { get; set; }

        [JsonPropertyName("location")]
        public string Location { get; set; }

        [JsonPropertyName("facebookUrl")]
        public string FacebookUrl { get; set; }

        [JsonPropertyName("twitterUrl")]
        public string TwitterUrl { get; set; }

        [JsonPropertyName("personalWebsite")]
        public string PersonalWebsite { get; set; }

        [JsonPropertyName("motivation")]
        public string Motivation { get; set; }

        [JsonPropertyName("bio")]
        public string Bio { get; set; }

        [JsonPropertyName("primaryActivity")]
        public string PrimaryActivity { get; set; }

        [JsonPropertyName("favoriteActivityTypes")]
        public string[] FavoriteActivityTypes { get; set; }

        [JsonPropertyName("runningTrainingSpeed")]
        public float? RunningTrainingSpeed { get; set; }

        [JsonPropertyName("cyclingTrainingSpeed")]
        public float? CyclingTrainingSpeed { get; set; }

        [JsonPropertyName("favoriteCyclingActivityTypes")]
        public string[] favoriteCyclingActivityTypes { get; set; }

        [JsonPropertyName("cyclingClassification")]
        public object CyclingClassification { get; set; }

        [JsonPropertyName("cyclingMaxAvgPower")]
        public float? CyclingMaxAvgPower { get; set; }

        [JsonPropertyName("swimmingTrainingSpeed")]
        public float? SwimmingTrainingSpeed { get; set; }

        [JsonPropertyName("profileVisibility")]
        public string ProfileVisibility { get; set; }

        [JsonPropertyName("activityStartVisibility")]
        public string ActivityStartVisibility { get; set; }

        [JsonPropertyName("activityMapVisibility")]
        public string ActivityMapVisibility { get; set; }

        [JsonPropertyName("courseVisibility")]
        public string CourseVisibility { get; set; }

        [JsonPropertyName("activityHeartRateVisibility")]
        public string ActivityHeartRateVisibility { get; set; }

        [JsonPropertyName("activityPowerVisibility")]
        public string ActivityPowerVisibility { get; set; }

        [JsonPropertyName("badgeVisibility")]
        public string BadgeVisibility { get; set; }

        [JsonPropertyName("showAge")]
        public bool ShowAge { get; set; }

        [JsonPropertyName("showWeight")]
        public bool ShowWeight { get; set; }

        [JsonPropertyName("showHeight")]
        public bool ShowHeight { get; set; }

        [JsonPropertyName("showWeightClass")]
        public bool ShowWeightClass { get; set; }

        [JsonPropertyName("showAgeRange")]
        public bool ShowAgeRange { get; set; }

        [JsonPropertyName("showGender")]
        public bool ShowGender { get; set; }

        [JsonPropertyName("showActivityClass")]
        public bool ShowActivityClass { get; set; }

        [JsonPropertyName("showVO2Max")]
        public bool ShowVO2Max { get; set; }

        [JsonPropertyName("showPersonalRecords")]
        public bool ShowPersonalRecords { get; set; }

        [JsonPropertyName("showLast12Months")]
        public bool ShowLast12Months { get; set; }

        [JsonPropertyName("showLifetimeTotals")]
        public bool ShowLifetimeTotals { get; set; }

        [JsonPropertyName("showUpcomingEvents")]
        public bool ShowUpcomingEvents { get; set; }

        [JsonPropertyName("showRecentFavorites")]
        public bool ShowRecentFavorites { get; set; }

        [JsonPropertyName("showRecentDevice")]
        public bool ShowRecentDevice { get; set; }

        [JsonPropertyName("showRecentGear")]
        public bool ShowRecentGear { get; set; }

        [JsonPropertyName("showBadges")]
        public bool ShowBadges { get; set; }

        [JsonPropertyName("otherActivity")]
        public string OtherActivity { get; set; }

        [JsonPropertyName("otherPrimaryActivity")]
        public string OtherPrimaryActivity { get; set; }

        [JsonPropertyName("otherMotivation")]
        public string OtherMotivation { get; set; }

        [JsonPropertyName("userRoles")]
        public string[] UserRoles { get; set; }

        [JsonPropertyName("nameApproved")]
        public bool NameApproved { get; set; }

        [JsonPropertyName("userProfileFullName")]
        public string UserProfileFullName { get; set; }

        [JsonPropertyName("makeGolfScorecardsPrivate")]
        public bool MakeGolfScorecardsPrivate { get; set; }

        [JsonPropertyName("allowGolfLiveScoring")]
        public bool AllowGolfLiveScoring { get; set; }

        [JsonPropertyName("allowGolfScoringByConnections")]
        public bool AllowGolfScoringByConnections { get; set; }

        [JsonPropertyName("userLevel")]
        public int? UserLevel { get; set; }

        [JsonPropertyName("userPoint")]
        public int? UserPoint { get; set; }

        [JsonPropertyName("levelUpdateDate")]
        public DateTime LevelUpdateDate { get; set; }

        [JsonPropertyName("levelIsViewed")]
        public bool LevelIsViewed { get; set; }

        [JsonPropertyName("levelPointThreshold")]
        public int? LevelPointThreshold { get; set; }

        [JsonPropertyName("userPointOffset")]
        public int? UserPointOffset { get; set; }

        [JsonPropertyName("userPro")]
        public bool IsUserPro { get; set; }
    }

}
