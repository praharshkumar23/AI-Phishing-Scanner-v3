<div align="center">

# 📊 Splunk Dashboard for Web Traffic Logs

![Splunk](https://img.shields.io/badge/Splunk-000000?style=for-the-badge&logo=splunk&logoColor=white)
![Apache](https://img.shields.io/badge/Apache-CA2136?style=for-the-badge&logo=apache&logoColor=white)
![JSON](https://img.shields.io/badge/JSON-000000?style=for-the-badge&logo=json&logoColor=white)
![SIEM](https://img.shields.io/badge/SIEM-Security-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Project-Completed-success?style=for-the-badge)

<img width="1728" height="550" alt="image" src="https://github.com/user-attachments/assets/a60f726e-f772-4fdc-a698-b37c3e3c34a8" />

</div>

## 📌 Project Overview
This project demonstrates the creation of an **interactive Splunk dashboard** to analyze **Apache Web Traffic Logs** in JSON format.  
The dashboard provides real-time insights into web activity, error trends, top resources, user IPs, and geographic traffic distribution.

It is designed for **web monitoring, security analysis, and performance troubleshooting**.

---

## 🎯 Objectives
- Analyze overall web traffic volume
- Monitor successful and failed HTTP responses
- Identify top requested URIs
- Track top users by IP address
- Visualize web traffic geographically using a Choropleth Map

---

## 🛠️ Tech Stack
- **Splunk Enterprise**
- **Apache Web Access Logs (JSON format)**
- **SPL (Search Processing Language)**

---

## 📂 Dataset Details
- **Source**: `apache_mixed_access_full (1).json`
- **Host**: `webserver`
- **Sourcetype**: `_json`
- **Key Fields**:
  - `ip`
  - `method`
  - `uri`
  - `status`
  - `_time`

---

## ⚙️ Lab Setup & Configuration

### 1️⃣ Data Ingestion
1. Login to Splunk as **Administrator**
2. Navigate to:  
```

Settings → Add Data → Upload

````
<img width="1919" height="963" alt="1" src="https://github.com/user-attachments/assets/e1c658ee-f45d-41d4-b84b-3959a461ec4c" />
<img width="1919" height="964" alt="2" src="https://github.com/user-attachments/assets/8117a740-d6ef-414c-9cbe-4be1858678b1" />
<img width="1919" height="963" alt="3" src="https://github.com/user-attachments/assets/15dc8825-d719-4044-b610-729bf318b348" />

3. Upload `apache_logs.json`
<img width="1919" height="963" alt="4" src="https://github.com/user-attachments/assets/93051fc2-36e7-40d7-b252-cdb2a1b5f21a" />
<img width="1918" height="959" alt="5" src="https://github.com/user-attachments/assets/77ce8b1f-8157-4606-a136-837df8e71613" />
<img width="1919" height="1079" alt="6" src="https://github.com/user-attachments/assets/ed55e849-2393-4853-82f7-7e88d7436ece" />
<img width="1919" height="965" alt="7" src="https://github.com/user-attachments/assets/41ea4a1b-e874-4711-a3c7-5e4f129750ee" />

4. Set:
- Source Type: `_json`
- Host: `webserver`
<img width="1919" height="963" alt="8" src="https://github.com/user-attachments/assets/c0a50776-5bbb-4486-b662-c7d41420b090" />
<img width="1919" height="963" alt="9" src="https://github.com/user-attachments/assets/fdd0f4be-de64-4346-8db9-fc0dcacc2ae7" />
<img width="1919" height="960" alt="10" src="https://github.com/user-attachments/assets/3bd0eeb4-737b-4f71-84ae-3c821bad4b39" />
<img width="1919" height="962" alt="11" src="https://github.com/user-attachments/assets/b688a4df-41cb-480c-85a8-1b8df52e49a8" />

5. Review and submit
<img width="1919" height="961" alt="12" src="https://github.com/user-attachments/assets/98fe856b-c2b9-47bd-b616-4c37950d7a6b" />
<img width="1919" height="966" alt="13" src="https://github.com/user-attachments/assets/ca655c6a-feb3-434b-994a-fb231b96bec5" />

Verify ingestion:
```spl
source="apache_logs.json"
````

---

## 📊 Dashboard Creation

### Dashboard Details

* **Dashboard Name**: Web Traffic Logs Dashboard
* **Dashboard Type**: Classic Dashboard
* **Permissions**: Private
<img width="1919" height="963" alt="14" src="https://github.com/user-attachments/assets/d5ed37e3-b921-4e53-8454-92b0cff3edff" />
<img width="1919" height="965" alt="15" src="https://github.com/user-attachments/assets/dba5a3b6-e294-482a-b801-0f07121bffb3" />
<img width="1919" height="966" alt="16" src="https://github.com/user-attachments/assets/a23e1b5a-14f5-4705-8f4a-76be2fe2c50c" />

---

## ⏱️ Task 0: Time Range Input

A shared time picker is used to ensure consistency across all panels.

* **Label**: Time Range
* **Token**: `time_range`

> All panels use the shared time picker token `time_range`.
<img width="1919" height="964" alt="17" src="https://github.com/user-attachments/assets/f2c58ad0-2ad2-4277-b8d1-0025a0538b0a" />
<img width="1919" height="966" alt="18" src="https://github.com/user-attachments/assets/24a441b0-0dc5-4060-96d7-dfcae9af0a76" />
<img width="1919" height="963" alt="19" src="https://github.com/user-attachments/assets/98359c3a-704a-434e-a8e0-dccaf7d99f60" />
<img width="1919" height="962" alt="20" src="https://github.com/user-attachments/assets/ca572828-6f52-4e81-b75f-6ec29be5890c" />
<img width="1919" height="967" alt="21" src="https://github.com/user-attachments/assets/ebcabe36-97dc-4b3e-b2c9-2e321bf4d75c" />
<img width="1919" height="964" alt="22" src="https://github.com/user-attachments/assets/95857fe4-72e4-41b6-a6fe-93a96c1361da" />
<img width="1919" height="963" alt="23" src="https://github.com/user-attachments/assets/a9fb7f4d-e1cc-416e-ac20-c261bb708f0f" />
<img width="1919" height="963" alt="24" src="https://github.com/user-attachments/assets/a71f80a8-bc62-4b0e-858b-6faf0bd37bec" />
<img width="1919" height="963" alt="25" src="https://github.com/user-attachments/assets/d2bdb1d9-4983-44ac-a3aa-f92414b58bf8" />

---

## 📈 Task 1: Web Activities

### 🔹 Total Web Requests

**Visualization**: Single Value

```spl
source="apache_logs.json" host="webserver" sourcetype="_json"
| stats count AS "Total Web Requests"
```
<img width="1919" height="964" alt="26" src="https://github.com/user-attachments/assets/05370e00-2534-431c-9c53-cf099a35a450" />
<img width="1917" height="965" alt="27" src="https://github.com/user-attachments/assets/9c42f43f-016d-438e-9f9d-1d710ba5a4f6" />
<img width="1919" height="964" alt="28" src="https://github.com/user-attachments/assets/7681cc22-6dfb-4625-b452-369d497918e6" />
<img width="1919" height="967" alt="29" src="https://github.com/user-attachments/assets/f6d255cb-173e-460e-b020-cf871df8a6a4" />
<img width="1919" height="964" alt="30" src="https://github.com/user-attachments/assets/b3a09dd8-2654-43e0-9341-6e913b193dca" />
<img width="1919" height="965" alt="31" src="https://github.com/user-attachments/assets/d6f2aa68-68cd-4cf0-af65-847900ade8c0" />
<img width="1919" height="964" alt="32" src="https://github.com/user-attachments/assets/b36e0bf2-5721-4182-89aa-a6714c55c23e" />
<img width="1919" height="967" alt="33" src="https://github.com/user-attachments/assets/b2bd1ff5-2df7-4933-9111-404c8a30e7d6" />
<img width="1919" height="967" alt="34" src="https://github.com/user-attachments/assets/fbd1f4fe-4f76-4f0e-972f-4aa2b69786ca" />
<img width="1919" height="966" alt="35" src="https://github.com/user-attachments/assets/c98ebcae-9c7d-4d0d-bd87-e3a0781060bb" />
<img width="1919" height="967" alt="36" src="https://github.com/user-attachments/assets/031c81e5-626a-4787-94fa-707321feba40" />
<img width="1919" height="966" alt="37" src="https://github.com/user-attachments/assets/60930f37-a09e-413e-9c3e-5cf2bb8d0959" />
<img width="1919" height="967" alt="38" src="https://github.com/user-attachments/assets/0aa6322d-9360-4196-a2a3-61b9b79c010c" />
<img width="1919" height="966" alt="39" src="https://github.com/user-attachments/assets/367a0dbc-f806-4d49-b4e3-6711115df3b1" />
<img width="1919" height="967" alt="40" src="https://github.com/user-attachments/assets/902f21f9-d075-4e41-ad20-76a76f58f5fe" />
<img width="1919" height="964" alt="41" src="https://github.com/user-attachments/assets/63c6f64d-707b-4cb9-8783-dc783688805b" />

---

### 🔹 Successful Responses (200 OK)

**Visualization**: Single Value

```spl
source="apache_mixed_logs.json" host="webserver" sourcetype="_json" method=GET status=200
| stats count AS "Successful Responses"
```
<img width="1919" height="964" alt="42" src="https://github.com/user-attachments/assets/2e2efe0b-cd0e-4337-897f-f4e2c726a228" />
<img width="1919" height="964" alt="43" src="https://github.com/user-attachments/assets/a0bad5f1-d765-4b3b-90bc-05b1522cb124" />
<img width="1919" height="964" alt="44" src="https://github.com/user-attachments/assets/5a40cb5a-192a-4381-81a9-ed09c6a078c1" />
<img width="1919" height="966" alt="45" src="https://github.com/user-attachments/assets/b6f0e4ad-75d8-4912-beb2-31c7d659e8a3" />
<img width="1919" height="965" alt="46" src="https://github.com/user-attachments/assets/a8bfba9e-65f2-48a1-9519-c91eeffabeeb" />
<img width="1919" height="968" alt="47" src="https://github.com/user-attachments/assets/32703d17-722f-4743-a697-2dccb28fe098" />
<img width="1919" height="967" alt="48" src="https://github.com/user-attachments/assets/0eb8f477-02d2-47c7-88ec-76c5dc66ac12" />
<img width="1919" height="968" alt="49" src="https://github.com/user-attachments/assets/240434b4-2287-4454-946f-ea1529220ccb" />

---

### 🔹 Client Errors (4xx)

**Visualization**: Single Value

```spl
source="apache_mixed_access_full (1).json" host="webserver" sourcetype="_json"
| where status>=400 AND status<500
| stats count AS "Client Errors"
```
<img width="1919" height="967" alt="50" src="https://github.com/user-attachments/assets/a0fd2efb-b646-45c1-a070-7587e6483b03" />
<img width="1919" height="970" alt="51" src="https://github.com/user-attachments/assets/1ef29379-baa2-4699-8621-a0913bb0aea9" />
<img width="1919" height="968" alt="52" src="https://github.com/user-attachments/assets/4a9550f0-7a39-4923-b9b8-007e5d886b46" />
<img width="1919" height="964" alt="53" src="https://github.com/user-attachments/assets/61e7fd48-40b4-48e0-9a5d-c75cc98e72ad" />
<img width="1919" height="966" alt="54" src="https://github.com/user-attachments/assets/6d91ad58-aaa8-4847-b7d7-1e5bd1701442" />
<img width="1919" height="963" alt="55" src="https://github.com/user-attachments/assets/edbaf631-05d1-4049-9b91-5d4defbfa0a7" />
<img width="1918" height="966" alt="56" src="https://github.com/user-attachments/assets/a7a6003f-9da3-47e0-9cac-9aa75a7d2034" />

---

### 🔹 Server Errors (5xx)

**Visualization**: Single Value

```spl
source="apache_logs.json" host="webserver" sourcetype="_json"
| where status>=500 AND status<600
| stats count AS "Server Errors"
```
<img width="1919" height="964" alt="57" src="https://github.com/user-attachments/assets/46c1b6a7-0dd6-4cea-b91c-9059387bd466" />
<img width="1919" height="968" alt="58" src="https://github.com/user-attachments/assets/a828df3f-d883-4a5c-bb5f-449203f1e062" />
<img width="1918" height="969" alt="59" src="https://github.com/user-attachments/assets/36ec4261-b259-4b1e-89d5-758eb5db6982" />
<img width="1919" height="968" alt="60" src="https://github.com/user-attachments/assets/c690fee5-3515-406b-acfc-39465ca6aedc" />
<img width="1919" height="961" alt="61" src="https://github.com/user-attachments/assets/13bf59ea-6a3f-48ed-a3c8-99d78dfe0d6a" />
<img width="1919" height="966" alt="62" src="https://github.com/user-attachments/assets/60a3fe67-9042-4fcd-9a6a-60a2c7d1016b" />
<img width="1919" height="966" alt="63" src="https://github.com/user-attachments/assets/0831d399-1f42-46c2-b0fb-2c2d105adb37" />
<img width="1919" height="964" alt="64" src="https://github.com/user-attachments/assets/98cc9d40-0aec-49fb-b5b8-3454fef59ccd" />

---

## 📊 Task 2: Web Statistics

### 🔹 Top Requested URIs

**Visualization**: Bar Chart

```spl
source="apache_logs.json" host="webserver" sourcetype="_json"
| stats count AS Hits by uri
| sort - Hits
```
<img width="1919" height="971" alt="65" src="https://github.com/user-attachments/assets/f332e846-ae48-4dc9-95b1-95291f59e0a3" />
<img width="1919" height="967" alt="66" src="https://github.com/user-attachments/assets/07d12630-1337-4830-9f9c-5c3babcc908d" />
<img width="1919" height="968" alt="67" src="https://github.com/user-attachments/assets/5ceaa8cb-403b-4c70-a123-2149dd1436f6" />
<img width="1919" height="965" alt="68" src="https://github.com/user-attachments/assets/fcda127a-af1b-41b1-b95c-2906e76a2491" />
<img width="1919" height="964" alt="69" src="https://github.com/user-attachments/assets/b1010c31-df9c-4292-98e8-ca7ae856cbab" />
<img width="1919" height="966" alt="70" src="https://github.com/user-attachments/assets/df8d7076-1d39-4c10-a5d0-42ed5a711cfa" />
<img width="1919" height="967" alt="71" src="https://github.com/user-attachments/assets/154aae7d-c826-4d63-813e-65f714b8f718" />
<img width="1919" height="972" alt="72" src="https://github.com/user-attachments/assets/be541cfc-58ab-41fb-ba7f-99bf0e437633" />
<img width="1919" height="969" alt="73" src="https://github.com/user-attachments/assets/3e7df434-270c-444e-bfc9-86efa82123f2" />

---

### 🔹 Top Users by IP Address

**Visualization**: Bar Chart

```spl
source="apache_logs.json" host="webserver" sourcetype="_json"
| stats count AS Requests by ip
| sort - Requests
```
<img width="1919" height="969" alt="74" src="https://github.com/user-attachments/assets/98b00d02-9944-471b-b68c-44dc25a84f88" />
<img width="1919" height="968" alt="75" src="https://github.com/user-attachments/assets/528ff3b8-aa85-4702-bd1a-2d9de73b25d0" />
<img width="1919" height="970" alt="76" src="https://github.com/user-attachments/assets/270ef4a4-53c9-471a-ad13-5b567d21f01d" />
<img width="1919" height="966" alt="77" src="https://github.com/user-attachments/assets/be538bfa-8963-4a08-b050-a8afe6a51d89" />
<img width="1919" height="967" alt="78" src="https://github.com/user-attachments/assets/d381b012-7716-4b7d-b9e0-674fafb5f301" />
<img width="1919" height="965" alt="79" src="https://github.com/user-attachments/assets/5c3f9b70-bae4-4d06-bf98-82161bde5e5d" />
<img width="1919" height="966" alt="81" src="https://github.com/user-attachments/assets/859e3aa9-faee-4062-b867-d3bb1ca730d6" />
<img width="1919" height="966" alt="82" src="https://github.com/user-attachments/assets/ed313093-29cc-4b03-8372-1e6519517aea" />
<img width="1919" height="967" alt="83" src="https://github.com/user-attachments/assets/206372f7-498e-4062-97e1-a8b2373612dd" />

---

## 🌍 Task 3: Web Traffic by Client IP (Geographic View)

### 🔹 Choropleth Map

**Visualization**: Choropleth Map

```spl
source="apache_mixed_access_full (1).json" host="webserver" sourcetype="_json" method=GET
| table ip
| iplocation ip
| stats count by Country
| geom geo_countries featureIdField="Country"
```
<img width="1918" height="964" alt="84" src="https://github.com/user-attachments/assets/f8692378-76a0-4314-9d81-2089ca374331" />
<img width="1919" height="967" alt="85" src="https://github.com/user-attachments/assets/58fc6232-8d3a-4ce2-bc19-fa8f3d2a5c0f" />
<img width="1918" height="966" alt="86" src="https://github.com/user-attachments/assets/22ba7412-bee9-475e-b293-c2b75368efc6" />
<img width="1919" height="963" alt="87" src="https://github.com/user-attachments/assets/be72d3f7-a5e2-425d-86f3-d59fbe2d68c9" />
<img width="1919" height="969" alt="88" src="https://github.com/user-attachments/assets/0109e70e-5661-4704-9c9d-d9165841852f" />
<img width="1919" height="965" alt="89" src="https://github.com/user-attachments/assets/9dd69d10-e7d6-4075-a2fc-70e5c7432e16" />
<img width="1919" height="1079" alt="90" src="https://github.com/user-attachments/assets/7b5be4eb-d873-4606-bff6-0718a8514e9f" />

---

## ✅ Key Features

* 📊 Real-time traffic monitoring
* 🚨 Error detection (4xx & 5xx)
* 🌐 Geographic traffic visualization
* 🔍 Insight into popular resources and users
* 🔐 Useful for security and anomaly detection

---

## 📌 Use Cases

* Web server monitoring
* Security analysis
* Traffic trend analysis
* Performance troubleshooting
* Academic and lab submissions

---

## 🧾 Conclusion

This project delivers a **comprehensive Splunk dashboard** for analyzing web traffic logs using SPL queries and visual analytics.
It enables administrators and security analysts to quickly understand traffic behavior, detect anomalies, and make informed decisions.

---

## 📚 Future Enhancements

* Add alerts for high error rates
* Time-series trend analysis
* Brute-force or suspicious IP detection
* Integration with SIEM use cases

---

