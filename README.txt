MASWER ATTEND - Neumorphic + Supabase + Netlify
===============================================
Employee phone se QR scan -> /scan -> EMP ID + shift -> Punch In/Out
-> Supabase me save -> Admin panel me turant dikhta hai.

STEP 1 - SUPABASE (database)
  supabase.com -> New project -> Project > Connect ->
  "Transaction pooler" URI copy karo (port 6543), [YOUR-PASSWORD] ki jagah apna password.
  Yehi DATABASE_URL hai. Tables pehli request par apne aap ban jaate hain.

STEP 2 - GITHUB
  github.com -> New repository (jaise: maswer-attend) -> "uploading an existing file"
  Is folder ki saari files/folders drag-drop karo
  (node_modules, .env upload NAHI karna - .gitignore ye sambhal leta hai) -> Commit.

STEP 3 - NETLIFY
  app.netlify.com -> Add new site -> Import from Git -> GitHub repo chuno.
  Build settings netlify.toml se apne aap aa jaati hain (kuch badalna nahi).
  Deploy se PEHLE: Site configuration > Environment variables me daalo:
     DATABASE_URL    = Supabase wali URI
     ADMIN_PASSWORD  = apna naya admin password
     EDIT_PIN        = apna naya PIN
     SESSION_SECRET  = koi bhi lamba random text
     APP_URL         = (deploy ke baad site ka URL, jaise https://maswer.netlify.app)
  Phir Deploy. APP_URL baad me daalo to "Trigger deploy" dobara karo.

STEP 4 - USE
  Site kholo -> Login (IT001 + IT_PASSWORD, IT tab) -> QR Code tab -> print karo.
  Employees apne phone se wahi QR scan karenge. Admin > Location me office GPS save karo.

PC par local test: START.bat (DATABASE_URL na ho to data/ folder use hota hai).
Security: admin API login ke bina band hain. ADMIN_PASSWORD aur EDIT_PIN zaroor badlo.

IT LOGIN = POORA ACCESS (naya)
  Pehla IT login server khud banata hai: IT_ID (default IT001) + IT_PASSWORD (env me set karo;
  na kiya to ChangeMe@123 — turant badlo, IT Users panel se).
  Login page par "IT" tab se login karo. IT ke paas SAB kuch hai:
   - Admins panel: Admin ID banao (ID, naam, password, kaun si locations dekh sakta hai ya Sab).
   - Projects panel: Project ID + naam banao. Phir Location panel me us project ke andar location jodo (lat, lng, radius).
     Location save karte hi us location ka QR ban jata hai (QR panel me sab locations ke QR, print/download).
   - Har location ka apna QR: us location ke employees jab apna QR scan karenge to attendance lag jayegi.
     Dusri location ka employee us QR par reject hota hai.
   - Employees: har employee ko ek location assign karo (card me dropdown) — wo sirf usi geofence me punch kar paayega.
   - Sab locations ki attendance: upar "Sab locations" filter se ek location ya sab dekho; Excel export bhi.
   - Attendance add / edit / delete — bina PIN ke. Bypass bhi bina PIN.
   - IT Tools (Phone Unlock) aur IT Users (aur IT login banao).
  Admin (IT ka banaya hua) sirf apni locations ki employees/attendance dekhta hai (sirf dekhna + employees add/delete + QR + export);
  locations / admins / IT manage nahi kar sakta.
  Purani single location apne aap "locations" me migrate ho jaati hai.
  Phone Unlock: employee ka phone kho gaya/badla ho to us din ka phone-lock hat jaata hai.
  Galat password 5 baar -> 15 minute ke liye rok.


CORPORATE STAFF (HQ / regional offices)
  1. Projects -> new Project, e.g. ID CORP, name "Corporate Office".
  2. Locations -> add HQ (and Regional Office ...) under project CORP. Each location gets its own QR.
  3. Employees -> add corporate staff with a Department (HR, Accounts, Sales ...) and their main location.
  4. Employee "Edit" -> tick extra locations if the person also works from another office / site:
     they can scan the QR of any allowed location; the record shows where they punched.
  5. Admins -> create a manager ID with "Departments" (e.g. HR) to see only that department,
     or leave Departments empty to see everyone in the chosen locations.
  6. Dashboards / Excel have a Department filter (top bar) and a Department column.


HR MODULE (salary, payslips, documents, audit)
  EMPLOYEE ID   Auto: EMP001, EMP002 ... (safe when two people add at once; cannot be edited).
                Employee master: name, phone, designation, joining date, monthly salary, photo, Active toggle.
                Inactive employees cannot punch in.
  DOCUMENTS     Employees -> Edit -> Documents: Aadhaar / PAN / Photo / Offer letter / Bank / Other.
                PDF, JPG, PNG, max 5 MB. View, Download, Replace, Delete. Private; only logged-in HR/IT
                with the "documents" permission (photo is visible to any HR in scope).
                STORAGE: set SUPABASE_URL + SUPABASE_SERVICE_KEY (service_role key, never put it in the browser).
                A private bucket "hr-documents" is created automatically. Without these, files go to data/uploads
                (fine for a PC/VPS, NOT for Netlify — it has no disk).
  SALARY        Salary tab. Per-day = monthly / (actual days in month, or fixed 30 — IT sets this).
                Present = 1, Half day = 0.5 (worked hours below the limit), Absent = 0.
                Weekly off (default Sunday) and listed holidays are paid. Optional overtime, late-mark deduction.
                Advances can be added per month. Calendar table shows every day and the running total.
                Missed punch-out = "Incomplete" (unpaid, red) until someone fixes it (Missed Punch-outs tab).
  PAYSLIP       "Generate payslip" = draft (version +1). "Finalize" locks the month for that employee:
                attendance edits and advances return "finalized". Number format PS-2026-10-EMP001.
                PDF download; Share = signed link valid 7 days (opens WhatsApp; link is copied for email).
                Only IT can Unlock (reason required, written to the audit log).
  PERMISSIONS   IT creates HR logins and ticks: salary & payslips / documents / edit-add-delete punches.
                All three are ON by default (untick to restrict a HR login). IT has everything, plus the Audit Log (IT only).
  AUDIT LOG     IT -> Audit Log. Every punch edit/add/delete (reason mandatory), salary change, payslip finalize/unlock,
                document upload/delete, employee deactivation.
  COMPANY RULES IT -> Company & Salary Rules: name, address, logo, 30-day vs calendar, half-day hours, week offs,
                holidays, overtime, late rules. Stored in the "settings" table (one row), so each client can differ.
  NIGHT SHIFT   Punch-out looks for the OPEN punch-in (today's, or yesterday's if less than 20 h old), not just
                the calendar date. After punching out, a new punch-in is blocked for 6 hours.
  Run once on an existing Supabase: paste supabase-schema.sql in the SQL editor (safe to repeat).


SITE MANAGERS (state-wise, view only)
  28 built-in state codes: Gujarat 8101, Rajasthan 8102, Maharashtra 8103, Madhya Pradesh 8104, Uttar Pradesh 8105,
  Haryana 8106, Punjab 8107, Himachal Pradesh 8108, Uttarakhand 8109, Bihar 8110, Jharkhand 8111, West Bengal 8112,
  Odisha 8113, Chhattisgarh 8114, Karnataka 8115, Tamil Nadu 8116, Kerala 8117, Andhra Pradesh 8118, Telangana 8119,
  Goa 8120, Assam 8121, Meghalaya 8122, Manipur 8123, Mizoram 8124, Nagaland 8125, Tripura 8126,
  Arunachal Pradesh 8127, Sikkim 8128.   (Union Territories are not included.)
  Projects: choose the State when you add/edit a project -> its code is saved automatically.
  Projects & Sites -> Site Managers (IT or HR): create ID + password + state codes (e.g. 8101, 8103).
  Login page -> "Site Manager" tab. A manager sees attendance (Attendance, Monthly Report, Site Watch, Excel)
  for ALL projects in his states, including projects added later. Cannot see employees, salary or settings, cannot edit.
  Existing projects have no state until you edit them and pick one.
