# Project: Job Tracker Cockpit

**Date:** April 2026  
**Author:** William Quattlebaum  
**Environment:** Local/private workflow application on Clawdbot

---

## Overview

Built a private local job-application cockpit to turn a messy job hunt into a usable workflow system.

Instead of treating job applications like scattered emails and random notes, this project consolidates the workflow into one operational dashboard that supports application tracking, follow-up management, recruiter notes, lead intake, and cover-letter generation.

---

## Why I Built It

The original job-hunt process was messy and inefficient:

- application confirmations mixed with junk alerts and duplicate notifications
- inconsistent follow-up tracking
- recruiter details scattered across notes and email history
- no single place to manage fresh leads and next actions
- repetitive manual work when drafting tailored cover letters

The cockpit was built to reduce that friction and create a cleaner, more repeatable process.

---

## Core Features

### 1. Curated Application Tracking
- Separates real applications from noisy confirmations and alert emails
- Creates a curated working set without destroying raw source data
- Supports override logic for cleaning bad company and role records

### 2. Daily Queue and Action Buckets
- Groups work into next-step buckets such as follow-up, review, archive, and recent applications
- Generates a daily queue so the highest-value tasks are visible immediately
- Adds urgency scoring to help prioritize effort

### 3. Recruiter / Follow-Up Editor
- Browser-based editor for recruiter emails, notes, and follow-up status
- Writes updates back into the working data set
- Regenerates the cockpit after changes so the dashboard stays current

### 4. Manual Lead Entry
- Lets new leads be added directly into the system from the browser
- Useful when a job is found on LinkedIn, Handshake, or a company site before the automated hunter captures it

### 5. Cover Letter Generator
- Generates draft cover letters from a job link, optional pasted description, and selected resume mode
- Supports different modes such as SOC, internship, and help desk bridge
- Reduces repeated application-writing effort while keeping drafts tailored to the role type

---

## Technical Design

### Stack
- **Python** for data processing, update scripts, and local service logic
- **HTML/CSS/JavaScript** for the browser UI
- **JSON** for local state, curated application data, and cockpit outputs
- **systemd** for keeping the dashboard service persistent on the host

### Architecture
- raw application source file preserved
- curated application layer for cleaned operational data
- override layer for recurring bad records
- generated dashboard JSON + markdown outputs
- local browser UI served through a lightweight Python server
- small local API for write-back actions

---

## What It Demonstrates

This project demonstrates:

- workflow automation
- local tool building for a real operational need
- data cleanup and normalization
- simple backend/API design
- front-end dashboard development
- systemd service deployment and maintenance
- practical problem solving around usability, persistence, and repeated task reduction

---

## Outcome

The Job Tracker Cockpit turned the job search process into a more usable system by:

- reducing noise from low-value job-email clutter
- making follow-ups and recruiter tracking easier to manage
- centralizing fresh leads and application progress
- reducing repeated effort through built-in cover letter generation

This is a private/local operational tool rather than a public SaaS product, but it reflects the same design thinking used in internal workflow applications and operations dashboards.

---

## Notes

Because the tool is local/private, it is presented in the portfolio as a documented project rather than a public live demo.
