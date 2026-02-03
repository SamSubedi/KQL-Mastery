# KQL-Mastery

# Introduction: Kusto Query Language (KQL) is a read-only, declarative language for querying and analyzing large datasets efficiently. It is primarily used in Microsoft Defender, Azure Sentinel, and Azure Data Explorer.

# KQL allows analysts to:

. Fetch logs, telemetry data, and operational events

. Perform anomaly detection and threat hunting

. Aggregate, filter, and join datasets for deeper insights

. All queries in KQL work with a tabular mindset: tables are returned, which can be manipulated using filters, joins, and summarization.


# Why KQL?

. Works seamlessly with Microsoft security tools

. Optimized for large datasets

. Supports advanced analytics without altering the underlying data

. Enables correlation of events across multiple sources for incident investigation


# Basic Concepts

. Tabular Operators: Operate on tables and return tables (e.g., where, join, union)

. Scalar Operators: Operate on single values and return a scalar (e.g., ==, has, +)

. Search Operator: Searches for text across tables and columns


# KQL Syntax: Nouns and Verbs

# Think of KQL in Noun-Verb terms:

. Nouns: Tables and columns (e.g., DeviceEvents, FileName, Timestamp)

. Verbs: Actions or operators applied to the nouns (e.g., where, summarize, join)

# Example:

DeviceEvents
| where FileName has "mimikatz"
| summarize count() by DeviceName

. DeviceEvents → noun (table)

. where, summarize → verbs (actions)


# Filtering and Searching

# Basic filtering:

DeviceEvents
| where Timestamp > ago(1d)
| where FileName has "rundll32"


# Using the search operator:

search in (DeviceEvents, DeviceProcessEvents) "mimikatz"
search FileName:"lsass"


# Handling nulls:

DeviceNetworkEvents
| where LocalPort < 1024 or isnull(LocalPort)


# Using variables (let) for reusable filters:

let suspiciousIPs = dynamic(["192.168.1.1", "10.10.0.1"]);
DeviceNetworkEvents
| where RemoteIP in (suspiciousIPs)

# Logical, String, and Numeric Operators

. Logical: and, or, !

. String operators: has, !has, contains, startswith, endswith

. Numeric operators: >, <, ==, !=, between

# Example:

DeviceEvents
| where FileName has "powershell" and EventType == 1
| where FileSize > 10000

# Aggregations and Statistical Functions

count(), dcount(), sum(), avg(), min(), max()

Example: Detect users with high login activity

let start_time = ago(24h);
SecurityEvent
| where TimeGenerated > start_time and EventID == 4624
| summarize login_count = count() by TargetUserName
| where login_count > 100

# Joins and Unions

# Union: Combine multiple tables

union DeviceEvents, DeviceProcessEvents
| where Timestamp > ago(7d)


# Join: Correlate data across tables

UserLoginEvents
| join kind=inner UserProfiles on UserId
| where Location !~ UserLocation

# Anomaly Detection

# Static anomaly detection: Using predefined thresholds

let whitelisted_users = dynamic(["SYSTEM", "svc-sccm"]);
SecurityEvent
| where EventID == 4624
| where TargetUserName !in (whitelisted_users)
| summarize login_count = count() by TargetUserName
| where login_count > 100


# Dynamic anomaly detection: Using historical baselines (advanced, for future expansion)

# Practical Examples

# 1. Detecting suspicious logins

SecurityEvent
| where EventID == 4625
| summarize failed_attempts = count() by TargetUserName, bin(TimeGenerated, 1h)
| where failed_attempts > 5


# 2. Correlating process creation with network connections

DeviceProcessEvents
| join kind=inner DeviceNetworkEvents on DeviceId
| where FileName has "powershell" and RemoteIP in ("8.8.8.8", "1.1.1.1")


# 3. Top 10 processes by CPU usage

DeviceProcessEvents
| summarize avg(CPU) by FileName
| top 10 by avg_CPU desc


# 4. Counting unique logins per user

SecurityEvent
| where EventID == 4624
| summarize unique_computers = dcount(Computer) by TargetUserName
| where unique_computers > 3

# Resources:

Microsoft KQL Documentation

Azure Sentinel

Microsoft 365 Defender

This README provides a practical, beginner-to-intermediate guide for learning KQL while also giving security analysts actionable examples for real-world use.
