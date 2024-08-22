import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider, useMutation, useQuery } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { createBrowserRouter, NavLink, RouterProvider, useNavigate } from 'react-router-dom';

// ============= API Helper =============
const API_URL = 'http://localhost:3000';
const fetcher = async (url, opts) => {
  const response = await fetch(`${API_URL}${url}`, {
    ...opts,
    credentials: 'include', // to allow cookies to be sent with the request
  });
  if (!response.ok) {
    // ok is a boolean that indicates if the response was successful (status in the range 200-299) or not.
    throw new Error('Something went wrong: ' + response.statusText);
  }

  // we don't need to await the json parsing,
  // we can just return the promise directly and React Query will handle it.
  // If we don't use react query, then we can always await when calling this function.
  return await response.json();
};

const api = {
  login: ({ username, password }) => {
    return fetcher(`/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });
  },
  register: ({ email, username, password }) => {
    return fetcher(`/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, username, password }),
    });
  },
  logout: () => {
    return fetcher(`/logout`);
  },
  getSecretSauce: () => {
    return fetcher(`/sauce`);
  },
};
// =====================================

// Initialize react, react-query, react-router-dom etc.
const container = document.getElementById('app');
const queryClient = new QueryClient();
const router = createBrowserRouter([
  {
    path: '/',
    element: <HomePage />,
  },
  {
    path: '/sauce',
    element: <SaucePage />,
  },
]);

createRoot(container).render(
  <QueryClientProvider client={queryClient}>
    <RouterProvider router={router} />
    <ReactQueryDevtools />
  </QueryClientProvider>
);
// =====================================

// Components / Pages
function HomePage() {
  const registerMutation = useMutation({
    mutationFn: api.register,
    onSuccess: () => {
      alert('Registration successful, you can now login!');
    },
    onError: (error) => {
      alert(`Registration failed, please try again. Error: ${error.message}`);
    },
  });

  const loginMutation = useMutation({
    mutationFn: api.login,
    onSuccess: () => {
      alert('Login successful, you can now access the secret sauce!');
    },
    onError: (error) => {
      alert(`Login failed, please try again. Error: ${error.message}`);
    },
  });

  const handleRegister = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const { email, username, password } = Object.fromEntries(formData.entries());
    console.log(`Registering user with email: ${email}, username: ${username}, password: ${password}`);
    registerMutation.mutate({ email, username, password });
  };

  const handleLogin = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const { username, password } = Object.fromEntries(formData.entries());
    console.log(`Logging in with username: ${formData.get('username')}, password: ${formData.get('password')}`);
    loginMutation.mutate({ username, password });
  };

  return (
    <div>
      <h1>Home</h1>
      {/* Registration Form */}
      <form id="registration-form" noValidate onSubmit={handleRegister}>
        <label>
          <span>Email: </span>
          <input name="email" type="email" placeholder="email" />
        </label>
        <label>
          <span>Username: </span>
          <input name="username" type="text" placeholder="username" />
        </label>
        <label>
          <span>Password: </span>
          <input name="password" type="password" placeholder="password" />
        </label>
        <button type="submit">Register</button>
      </form>

      <br />
      <hr />
      <br />

      {/* Login Form */}
      <form id="login-form" noValidate onSubmit={handleLogin}>
        <label>
          <span>Username: </span>
          <input name="username" type="username" placeholder="username" />
        </label>
        <label>
          <span>Password: </span>
          <input name="password" type="password" placeholder="password" />
        </label>
        <button type="submit">Login</button>
      </form>

      <br />
      <hr />
      <NavLink to="/sauce">Go to the secret sauce page</NavLink>
    </div>
  );
}

let sauceQueryKey = 'sauce';

function SaucePage() {
  const { data, isPending, isError, error } = useQuery({
    queryKey: sauceQueryKey,
    queryFn: api.getSecretSauce,
    retry: 0,
  });
  const navigate = useNavigate();

  const logoutMutation = useMutation({
    mutationFn: api.logout,
    onSuccess: () => {
      queryClient.clear(sauceQueryKey);
      alert('Logout successful!');
      navigate('/');
    },
    onError: (error) => {
      alert(`Logout failed, please try again. Error: ${error.message}`);
    },
  });

  const handleLogout = () => {
    console.log('Logging out...');
    logoutMutation.mutate();
  };

  if (isPending) {
    return <h1>Loading the sauce</h1>;
  }

  if (isError) {
    return <h1>Failed to load the sauce with error: ${error.message}</h1>;
  }

  // data.sauce because of this is what the API returns
  // return res.json({ sauce: 'the sauce is an image url' });
  // You might see a warning in your console in the browser about Third Part cookies or something like that, it's nothing special, ignore it.
  return (
    <div>
      <h1>Sauce</h1>
      <NavLink to="/">Go back to the home page</NavLink>
      <div>You are logged in!</div>
      <button onClick={handleLogout}>Click here to Logout!</button>
      <img src={data.sauce} alt="The secret sauce" />
    </div>
  );
}
