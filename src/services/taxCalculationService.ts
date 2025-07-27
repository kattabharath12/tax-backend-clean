
import { Decimal } from 'decimal.js';
import { TaxReturn, IncomeEntry, DeductionEntry, Dependent } from '@prisma/client';

export interface TaxReturnWithRelations extends TaxReturn {
  incomeEntries: IncomeEntry[];
  deductionEntries: DeductionEntry[];
  dependents: Dependent[];
}

export interface TaxCalculationResult {
  totalIncome: Decimal;
  adjustedGrossIncome: Decimal;
  standardDeduction: Decimal;
  itemizedDeduction: Decimal;
  taxableIncome: Decimal;
  taxLiability: Decimal;
  totalCredits: Decimal;
  refundAmount: Decimal;
  amountOwed: Decimal;
}

// 2023 Tax Brackets (Single)
const TAX_BRACKETS_SINGLE = [
  { min: 0, max: 11000, rate: 0.10 },
  { min: 11000, max: 44725, rate: 0.12 },
  { min: 44725, max: 95375, rate: 0.22 },
  { min: 95375, max: 182050, rate: 0.24 },
  { min: 182050, max: 231250, rate: 0.32 },
  { min: 231250, max: 578125, rate: 0.35 },
  { min: 578125, max: Infinity, rate: 0.37 }
];

// 2023 Tax Brackets (Married Filing Jointly)
const TAX_BRACKETS_MARRIED = [
  { min: 0, max: 22000, rate: 0.10 },
  { min: 22000, max: 89450, rate: 0.12 },
  { min: 89450, max: 190750, rate: 0.22 },
  { min: 190750, max: 364200, rate: 0.24 },
  { min: 364200, max: 462500, rate: 0.32 },
  { min: 462500, max: 693750, rate: 0.35 },
  { min: 693750, max: Infinity, rate: 0.37 }
];

// 2023 Standard Deductions
const STANDARD_DEDUCTIONS = {
  SINGLE: new Decimal(13850),
  MARRIED_FILING_JOINTLY: new Decimal(27700),
  MARRIED_FILING_SEPARATELY: new Decimal(13850),
  HEAD_OF_HOUSEHOLD: new Decimal(20800),
  QUALIFYING_SURVIVING_SPOUSE: new Decimal(27700)
};

export async function calculateTaxes(taxReturn: TaxReturnWithRelations): Promise<TaxCalculationResult> {
  // Calculate total income
  const totalIncome = taxReturn.incomeEntries.reduce(
    (sum, entry) => sum.plus(entry.amount),
    new Decimal(0)
  );

  // For simplicity, AGI equals total income (in reality, there are adjustments)
  const adjustedGrossIncome = totalIncome;

  // Calculate itemized deductions
  const itemizedDeduction = taxReturn.deductionEntries.reduce(
    (sum, entry) => sum.plus(entry.amount),
    new Decimal(0)
  );

  // Get standard deduction for filing status
  const standardDeduction = STANDARD_DEDUCTIONS[taxReturn.filingStatus] || STANDARD_DEDUCTIONS.SINGLE;

  // Use the higher of standard or itemized deduction
  const deductionToUse = Decimal.max(standardDeduction, itemizedDeduction);

  // Calculate taxable income
  const taxableIncome = Decimal.max(adjustedGrossIncome.minus(deductionToUse), new Decimal(0));

  // Calculate tax liability based on brackets
  const taxLiability = calculateTaxLiability(taxableIncome, taxReturn.filingStatus);

  // Calculate credits (simplified - just child tax credit for now)
  const totalCredits = calculateCredits(taxReturn);

  // Calculate final amounts
  const netTax = Decimal.max(taxLiability.minus(totalCredits), new Decimal(0));
  const refundAmount = totalCredits.greaterThan(taxLiability) ? totalCredits.minus(taxLiability) : new Decimal(0);
  const amountOwed = netTax;

  return {
    totalIncome,
    adjustedGrossIncome,
    standardDeduction,
    itemizedDeduction,
    taxableIncome,
    taxLiability,
    totalCredits,
    refundAmount,
    amountOwed
  };
}

function calculateTaxLiability(taxableIncome: Decimal, filingStatus: string): Decimal {
  const brackets = filingStatus === 'MARRIED_FILING_JOINTLY' || filingStatus === 'QUALIFYING_SURVIVING_SPOUSE'
    ? TAX_BRACKETS_MARRIED
    : TAX_BRACKETS_SINGLE;

  let tax = new Decimal(0);
  let remainingIncome = taxableIncome;

  for (const bracket of brackets) {
    if (remainingIncome.lessThanOrEqualTo(0)) break;

    const bracketMin = new Decimal(bracket.min);
    const bracketMax = new Decimal(bracket.max);
    const bracketRate = new Decimal(bracket.rate);

    const taxableInThisBracket = Decimal.min(
      remainingIncome,
      bracketMax.minus(bracketMin)
    );

    if (taxableInThisBracket.greaterThan(0)) {
      tax = tax.plus(taxableInThisBracket.times(bracketRate));
      remainingIncome = remainingIncome.minus(taxableInThisBracket);
    }
  }

  return tax;
}

function calculateCredits(taxReturn: TaxReturnWithRelations): Decimal {
  let credits = new Decimal(0);

  // Child Tax Credit (simplified)
  const qualifyingChildren = taxReturn.dependents.filter(dep => dep.isQualifyingChild);
  const childTaxCredit = new Decimal(qualifyingChildren.length).times(2000);
  credits = credits.plus(childTaxCredit);

  // Additional credits can be added here (EITC, education credits, etc.)

  return credits;
}

// Helper function to get tax brackets for a filing status
export function getTaxBrackets(filingStatus: string) {
  return filingStatus === 'MARRIED_FILING_JOINTLY' || filingStatus === 'QUALIFYING_SURVIVING_SPOUSE'
    ? TAX_BRACKETS_MARRIED
    : TAX_BRACKETS_SINGLE;
}

// Helper function to get standard deduction
export function getStandardDeduction(filingStatus: string): Decimal {
  return STANDARD_DEDUCTIONS[filingStatus as keyof typeof STANDARD_DEDUCTIONS] || STANDARD_DEDUCTIONS.SINGLE;
}
