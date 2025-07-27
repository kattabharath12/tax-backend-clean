
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { Decimal } from 'decimal.js';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // Create test users
  const hashedPassword = await bcrypt.hash('password123', 12);

  const testUser = await prisma.user.upsert({
    where: { email: 'test@example.com' },
    update: {},
    create: {
      email: 'test@example.com',
      name: 'Test User',
      password: hashedPassword,
    },
  });

  console.log('✅ Created test user:', testUser.email);

  // Create sample tax return
  const taxReturn = await prisma.taxReturn.upsert({
    where: {
      userId_taxYear: {
        userId: testUser.id,
        taxYear: 2023
      }
    },
    update: {},
    create: {
      userId: testUser.id,
      taxYear: 2023,
      filingStatus: 'SINGLE',
      firstName: 'Test',
      lastName: 'User',
      address: '123 Main St',
      city: 'Anytown',
      state: 'CA',
      zipCode: '12345',
      currentStep: 3,
      completedSteps: [1, 2],
      standardDeduction: new Decimal(13850),
    },
  });

  console.log('✅ Created sample tax return for 2023');

  // Create sample income entries
  await prisma.incomeEntry.createMany({
    data: [
      {
        taxReturnId: taxReturn.id,
        incomeType: 'W2_WAGES',
        description: 'Software Engineer Salary',
        amount: new Decimal(75000),
        employerName: 'Tech Corp',
        employerEIN: '12-3456789',
      },
      {
        taxReturnId: taxReturn.id,
        incomeType: 'INTEREST',
        description: 'Savings Account Interest',
        amount: new Decimal(250),
        payerName: 'First National Bank',
        payerTIN: '98-7654321',
      },
    ],
    skipDuplicates: true,
  });

  console.log('✅ Created sample income entries');

  // Create sample deduction entries
  await prisma.deductionEntry.createMany({
    data: [
      {
        taxReturnId: taxReturn.id,
        deductionType: 'CHARITABLE_CONTRIBUTIONS',
        description: 'Donations to local charity',
        amount: new Decimal(2500),
      },
      {
        taxReturnId: taxReturn.id,
        deductionType: 'STATE_LOCAL_TAXES',
        description: 'State income tax paid',
        amount: new Decimal(4200),
      },
    ],
    skipDuplicates: true,
  });

  console.log('✅ Created sample deduction entries');

  // Create sample dependent
  await prisma.dependent.create({
    data: {
      taxReturnId: taxReturn.id,
      firstName: 'Child',
      lastName: 'User',
      ssn: '123-45-6789',
      relationship: 'Son',
      birthDate: new Date('2015-06-15'),
      isQualifyingChild: true,
    },
  });

  console.log('✅ Created sample dependent');

  console.log('🎉 Database seed completed successfully!');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
