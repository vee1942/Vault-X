// Test script for the new authentication system
import fetch from 'node-fetch';

const BASE_URL = 'http://localhost:3001';

async function testAuth() {
  console.log('🧪 Testing Authentication System...\n');

  try {
    // Test 1: Sign up a new user
    console.log('1. Testing user signup...');
    const signupResponse = await fetch(`${BASE_URL}/api/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      })
    });
    
    const signupResult = await signupResponse.json();
    console.log('Signup result:', signupResult);
    
    if (!signupResponse.ok) {
      console.log('❌ Signup failed');
      return;
    }
    
    console.log('✅ Signup successful\n');

    // Test 2: Login with the created user
    console.log('2. Testing user login...');
    const loginResponse = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'password123'
      })
    });
    
    const loginResult = await loginResponse.json();
    console.log('Login result:', loginResult);
    
    if (!loginResponse.ok) {
      console.log('❌ Login failed');
      return;
    }
    
    console.log('✅ Login successful\n');

    // Test 3: Get user profile
    console.log('3. Testing profile retrieval...');
    const uid = loginResult.profile.uid;
    const profileResponse = await fetch(`${BASE_URL}/api/profile/${uid}`);
    const profileResult = await profileResponse.json();
    console.log('Profile result:', profileResult);
    
    if (!profileResponse.ok) {
      console.log('❌ Profile retrieval failed');
      return;
    }
    
    console.log('✅ Profile retrieval successful\n');

    // Test 4: Test duplicate email signup (should fail)
    console.log('4. Testing duplicate email signup (should fail)...');
    const duplicateResponse = await fetch(`${BASE_URL}/api/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'test@example.com',
        name: 'Another User',
        password: 'password456'
      })
    });
    
    const duplicateResult = await duplicateResponse.json();
    console.log('Duplicate signup result:', duplicateResult);
    
    if (duplicateResponse.ok) {
      console.log('❌ Duplicate signup should have failed');
    } else {
      console.log('✅ Duplicate signup correctly rejected\n');
    }

    // Test 5: Test wrong password login (should fail)
    console.log('5. Testing wrong password login (should fail)...');
    const wrongPassResponse = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'wrongpassword'
      })
    });
    
    const wrongPassResult = await wrongPassResponse.json();
    console.log('Wrong password login result:', wrongPassResult);
    
    if (wrongPassResponse.ok) {
      console.log('❌ Wrong password login should have failed');
    } else {
      console.log('✅ Wrong password login correctly rejected\n');
    }

    console.log('🎉 All authentication tests completed!');

  } catch (error) {
    console.error('❌ Test failed with error:', error.message);
  }
}

// Run the test
testAuth();
