import React, { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
  const [products, setProducts] = useState([]);
  const [token, setToken] = useState(localStorage.getItem('token'));

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const response = await axios.get(
          'https://api.sriinfosoft.com/products',
          {
            headers: { Authorization: `Bearer ${token}` },
          }
        );
        setProducts(response.data);
      } catch (error) {
        console.error('Failed to fetch products');
      }
    };

    if (token) {
      fetchProducts();
    }
  }, [token]);

  const handleLogin = async (email, password) => {
    try {
      const response = await axios.post('https://api.sriinfosoft.com/login', {
        email,
        password,
      });
      const { token } = response.data;
      localStorage.setItem('token', token);
      setToken(token);
    } catch (error) {
      console.error('Login failed');
    }
  };

  return <div>{/* Login and Product Management Components */}</div>;
}

export default App;
