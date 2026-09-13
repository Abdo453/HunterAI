"""
HunterAI Financial & Regulatory Risk Impact Calculator (V12.0)
==============================================================
Translates technical vulnerability findings into executive financial liabilities:
1. GDPR Article 83(5) maximum and expected fines (up to 4% of annual global turnover or €20M).
2. PCI-DSS v4.0 merchant bank non-compliance penalties & card reissuance costs.
3. HIPAA Security Rule Tier 1-4 statutory penalty cap assessments.
4. Business downtime losses and Digital Forensics & Incident Response (DFIR) costs.
5. Executive Financial Exposure Summary & Mitigation ROI.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DataSensitivityLevel(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL_CONFIDENTIAL = "INTERNAL_CONFIDENTIAL"
    PII_BASIC = "PII_BASIC"              # Names, emails, phone numbers
    FINANCIAL_PAYMENT = "FINANCIAL_PAYMENT"  # Credit cards, bank accounts (PCI)
    PROTECTED_HEALTH = "PROTECTED_HEALTH"    # Medical records, diagnoses (HIPAA)
    CREDENTIALS_AND_KEYS = "CREDENTIALS"     # Master secrets, root access


@dataclass
class FinancialExposureReport:
    cwe_id: str
    vulnerability_title: str
    affected_records_count: int
    annual_turnover_eur: float
    data_sensitivity: DataSensitivityLevel
    gdpr_max_fine_eur: float
    gdpr_estimated_fine_eur: float
    pci_dss_penalties_usd: float
    hipaa_penalties_usd: float
    downtime_loss_usd: float
    incident_response_cost_usd: float
    total_potential_exposure_usd: float
    mitigation_roi_multiplier: float
    executive_narrative: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "vulnerability_title": self.vulnerability_title,
            "affected_records_count": self.affected_records_count,
            "annual_turnover_eur": self.annual_turnover_eur,
            "data_sensitivity": self.data_sensitivity.value,
            "gdpr_max_fine_eur": round(self.gdpr_max_fine_eur, 2),
            "gdpr_estimated_fine_eur": round(self.gdpr_estimated_fine_eur, 2),
            "pci_dss_penalties_usd": round(self.pci_dss_penalties_usd, 2),
            "hipaa_penalties_usd": round(self.hipaa_penalties_usd, 2),
            "downtime_loss_usd": round(self.downtime_loss_usd, 2),
            "incident_response_cost_usd": round(self.incident_response_cost_usd, 2),
            "total_potential_exposure_usd": round(self.total_potential_exposure_usd, 2),
            "mitigation_roi_multiplier": round(self.mitigation_roi_multiplier, 1),
            "executive_narrative": self.executive_narrative,
        }


class FinancialImpactCalculator:
    """
    Computes statutory regulatory fines, merchant penalties, and operational losses.
    """

    EUR_TO_USD = 1.08  # Representative conversion rate

    @classmethod
    def calculate_gdpr_fine(
        cls,
        annual_turnover_eur: float,
        record_count: int,
        sensitivity: DataSensitivityLevel
    ) -> Tuple[float, float]:
        """
        Computes (max_fine_eur, estimated_fine_eur) under GDPR Article 83(5).
        Statutory Maximum: Higher of €20,000,000 or 4% of worldwide annual turnover.
        """
        statutory_cap = max(20_000_000.0, annual_turnover_eur * 0.04)

        if sensitivity in (DataSensitivityLevel.PUBLIC, DataSensitivityLevel.INTERNAL_CONFIDENTIAL):
            return 0.0, 0.0

        # Base scale depending on records compromised
        if record_count < 1_000:
            scale = 0.002  # 0.2% of turnover
        elif record_count < 50_000:
            scale = 0.010  # 1.0% of turnover
        elif record_count < 500_000:
            scale = 0.025  # 2.5% of turnover
        else:
            scale = 0.040  # Maximum 4%

        if sensitivity in (DataSensitivityLevel.PROTECTED_HEALTH, DataSensitivityLevel.FINANCIAL_PAYMENT):
            scale = min(0.04, scale * 1.5)

        estimated = min(statutory_cap, annual_turnover_eur * scale)
        # Baseline minimum sanction for significant corporate data breaches
        if record_count > 5_000:
            estimated = max(50_000.0, estimated)

        return statutory_cap, round(estimated, 2)

    @classmethod
    def calculate_pci_penalties(
        cls,
        record_count: int,
        sensitivity: DataSensitivityLevel
    ) -> float:
        """
        Computes PCI-DSS v4.0 non-compliance fines, forensic audit, and card replacement.
        """
        if sensitivity != DataSensitivityLevel.FINANCIAL_PAYMENT:
            return 0.0

        forensic_retainer = 50_000.0  # Mandatory PFI (Payment Card Forensics Investigator)
        card_reissuance_per_record = 6.50  # Bank average card reissuance cost
        merchant_bank_fine = 25_000.0  # Initial fine for card data exposure

        total_pci = forensic_retainer + merchant_bank_fine + (record_count * card_reissuance_per_record)
        return round(total_pci, 2)

    @classmethod
    def calculate_hipaa_penalties(
        cls,
        record_count: int,
        sensitivity: DataSensitivityLevel
    ) -> float:
        """
        Computes statutory penalties under HIPAA Security Rule (Tier 3/4 uncorrected neglect).
        Statutory Annual Cap: $1,919,173.
        """
        if sensitivity != DataSensitivityLevel.PROTECTED_HEALTH:
            return 0.0

        per_record_penalty = 100.0  # Tier 2/3 violation base
        raw_penalty = record_count * per_record_penalty
        statutory_cap = 1_919_173.0

        return round(min(statutory_cap, max(25_000.0, raw_penalty)), 2)

    @classmethod
    def calculate_operational_losses(
        cls,
        severity: str,
        hourly_downtime_cost_usd: float = 15_000.0
    ) -> Tuple[float, float]:
        """
        Computes (downtime_loss_usd, incident_response_cost_usd).
        """
        sev_upper = severity.upper()
        if "CRIT" in sev_upper:
            downtime_hours = 8.0
            ir_retainer = 75_000.0
        elif "HIGH" in sev_upper:
            downtime_hours = 3.0
            ir_retainer = 35_000.0
        elif "MED" in sev_upper:
            downtime_hours = 0.5
            ir_retainer = 10_000.0
        else:
            downtime_hours = 0.0
            ir_retainer = 2_500.0

        downtime_loss = downtime_hours * hourly_downtime_cost_usd
        return round(downtime_loss, 2), round(ir_retainer, 2)

    @classmethod
    def assess_full_exposure(
        cls,
        cwe_id: str,
        title: str,
        severity: str,
        affected_records: int = 10_000,
        annual_turnover_eur: float = 25_000_000.0,
        sensitivity: DataSensitivityLevel = DataSensitivityLevel.PII_BASIC,
        hourly_downtime_usd: float = 20_000.0
    ) -> FinancialExposureReport:
        gdpr_max, gdpr_est = cls.calculate_gdpr_fine(annual_turnover_eur, affected_records, sensitivity)
        pci_cost = cls.calculate_pci_penalties(affected_records, sensitivity)
        hipaa_cost = cls.calculate_hipaa_penalties(affected_records, sensitivity)
        downtime, ir_cost = cls.calculate_operational_losses(severity, hourly_downtime_usd)

        # Convert GDPR estimated fine to USD for aggregate total
        gdpr_usd = gdpr_est * cls.EUR_TO_USD
        total_usd = gdpr_usd + pci_cost + hipaa_cost + downtime + ir_cost

        # Assumed developer remediation patch cost: $5,000
        remediation_cost = 5_000.0
        roi_multiplier = max(1.0, total_usd / remediation_cost)

        narrative = (
            f"Vulnerability '{title}' exposes {affected_records:,} {sensitivity.value} records. "
            f"Expected regulatory & operational financial liability is estimated at ${total_usd:,.2f} USD "
            f"(including €{gdpr_est:,.2f} GDPR exposure). Remediating this defect immediately provides a "
            f"{roi_multiplier:.1f}x Return on Investment relative to incident response and regulatory fines."
        )

        return FinancialExposureReport(
            cwe_id=cwe_id,
            vulnerability_title=title,
            affected_records_count=affected_records,
            annual_turnover_eur=annual_turnover_eur,
            data_sensitivity=sensitivity,
            gdpr_max_fine_eur=gdpr_max,
            gdpr_estimated_fine_eur=gdpr_est,
            pci_dss_penalties_usd=pci_cost,
            hipaa_penalties_usd=hipaa_cost,
            downtime_loss_usd=downtime,
            incident_response_cost_usd=ir_cost,
            total_potential_exposure_usd=total_usd,
            mitigation_roi_multiplier=roi_multiplier,
            executive_narrative=narrative
        )
