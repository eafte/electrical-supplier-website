const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function setupAdmin() {
  console.log('\n🔧 Setting up admin user...\n');

  try {
    const seedPassword = process.env.SEED_ADMIN_PASSWORD || 'admin123';
    // Hash password
    const hashedPassword = await bcrypt.hash(seedPassword, 10);
    console.log('✓ Password hashed');

    // Upsert keeps a stable ID across runs and avoids cross-test interference
    // when multiple Jest workers run this script concurrently.
    const admin = await prisma.admin.upsert({
      where: { email: 'admin@electricalsupplier.com' },
      update: {
        password: hashedPassword,
        name: 'System Administrator',
        role: 'admin',
        isActive: true,
        twoFactorEnabled: false,
        twoFactorSecret: null,
        backupCodes: null,
      },
      create: {
        email: 'admin@electricalsupplier.com',
        password: hashedPassword,
        name: 'System Administrator',
        role: 'admin',
        isActive: true,
        twoFactorEnabled: false,
        twoFactorSecret: null,
        backupCodes: null,
      },
    });

    // Remove existing sessions so tests start from a clean auth state.
    await prisma.refreshToken.deleteMany({
      where: { adminId: admin.id },
    });

    console.log('\n✅ Admin user ready successfully!');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('ID:', admin.id);
    console.log('Email:', admin.email);
    console.log('Password: [REDACTED]');
    console.log('Role:', admin.role);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('\n🌐 Login at: http://localhost:5000/admin/login\n');

    // Verify we can read it back
    const verify = await prisma.admin.findUnique({
      where: { email: 'admin@electricalsupplier.com' }
    });

    if (verify) {
      console.log('✓ Verification: Admin user exists in database');

      // Test password
      const passwordMatch = await bcrypt.compare(seedPassword, verify.password);
      console.log(passwordMatch ? '✓ Verification: Password hash is correct' : '✗ Verification: Password hash is incorrect');
    }

  } catch (error) {
    console.error('\n❌ Error:', error.message);
    console.error(error);
  } finally {
    await prisma.$disconnect();
  }
}

setupAdmin();
