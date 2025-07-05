// Complete Domain Add Test Script for RedMail Admin Panel
// Instructions:
// 1. Open admin panel: http://localhost:3000/admin
// 2. Login with password: 'password'
// 3. Go to Settings page
// 4. Open browser console (F12)
// 5. Copy and paste this entire script
// 6. Run the test functions

// Function to login programmatically (if needed)
async function loginAdmin() {
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: 'password' })
        });
        
        const data = await response.json();
        if (data.success) {
            localStorage.setItem('adminToken', data.token);
            console.log('✅ Login successful! Token saved.');
            return data.token;
        } else {
            console.error('❌ Login failed:', data.error);
        }
    } catch (error) {
        console.error('❌ Login error:', error);
    }
}

// Function to test domain addition
async function testAddDomain(domainName = 'example.com') {
    try {
        console.log(`🧪 Testing domain addition for: ${domainName}`);
        
        // Check if we're on the settings page
        const settingsContent = document.getElementById('settings-content');
        if (!settingsContent || !settingsContent.classList.contains('active')) {
            console.warn('⚠️ Please navigate to Settings page first!');
            return;
        }
        
        // First, let's check if the form elements exist
        const addBtn = document.getElementById('addDomainBtn');
        const domainNameInput = document.getElementById('newDomainName');
        const domainStatusSelect = document.getElementById('newDomainStatus');
        const saveBtn = document.getElementById('saveDomainBtn');
        
        if (!addBtn || !domainNameInput || !domainStatusSelect || !saveBtn) {
            console.error('❌ Domain form elements not found!');
            return;
        }
        
        console.log('✅ Form elements found successfully');
        
        // Show the add domain form
        addBtn.click();
        console.log('📝 Add domain form opened');
        
        // Wait a bit for form to show
        await new Promise(resolve => setTimeout(resolve, 100));
        
        // Fill in test domain
        domainNameInput.value = domainName;
        domainStatusSelect.value = 'active';
        console.log(`📝 Form filled with domain: ${domainName}`);
        
        // Save the domain
        saveBtn.click();
        console.log('💾 Save button clicked');
        
        // Wait for the operation to complete
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        console.log('✅ Domain addition test completed!');
        
    } catch (error) {
        console.error('❌ Error testing domain addition:', error);
    }
}

// Function to check current domains
async function checkDomains() {
    try {
        const token = localStorage.getItem('adminToken');
        if (!token) {
            console.error('❌ No admin token found. Please login first.');
            return;
        }
        
        const response = await fetch('/api/admin/domains', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        console.log('📋 Current domains:', data);
        
        if (data.domains && data.domains.length > 0) {
            console.table(data.domains);
        } else {
            console.log('📭 No domains found');
        }
        
        return data;
    } catch (error) {
        console.error('❌ Error fetching domains:', error);
    }
}

// Function to test multiple domains
async function testMultipleDomains() {
    const testDomains = ['example.com', 'test.org', 'demo.net', 'sample.io'];
    
    console.log('🚀 Testing multiple domain additions...');
    
    for (let i = 0; i < testDomains.length; i++) {
        console.log(`\n--- Testing domain ${i + 1}/${testDomains.length}: ${testDomains[i]} ---`);
        await testAddDomain(testDomains[i]);
        
        // Wait between additions
        if (i < testDomains.length - 1) {
            console.log('⏳ Waiting 2 seconds before next domain...');
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
    
    console.log('\n🎉 Multiple domain test completed!');
    console.log('📋 Checking final domain list...');
    await checkDomains();
}

// Function to navigate to settings page
function goToSettings() {
    const settingsLink = document.querySelector('[data-page="settings"]');
    if (settingsLink) {
        settingsLink.click();
        console.log('📄 Navigated to Settings page');
    } else {
        console.error('❌ Settings link not found');
    }
}

// Instructions
console.log('🔧 Domain Add Test Script Loaded!');
console.log('\n📋 Available Functions:');
console.log('1. loginAdmin() - Login to admin panel');
console.log('2. goToSettings() - Navigate to Settings page');
console.log('3. checkDomains() - View current domains');
console.log('4. testAddDomain("domain.com") - Test adding a single domain');
console.log('5. testMultipleDomains() - Test adding multiple domains');
console.log('\n🚀 Quick Start:');
console.log('Run: goToSettings(); then testAddDomain("mydomain.com");');
console.log('\n💡 Note: Make sure you are logged in to admin panel first!');