
# LIBRARY API
  
## List of Contents
- ### [Introduction](#introduction)
- ### [Usage with Thunder Client](#usage-with-thunder-client)
- ### [Endpoints](#endpoints)


## Introduction
This library API utilizes a one-time use token for authenticated users, where each token has a lifespan of one minute. It requires the user to register and authenticate their username and password. The API has a total of 11 endpoints with three different categories. These are: [books](#books), [authors](#authors), and [users](#users) endpoints. Tokens are `HTTPOnly` thus offering high security against XSS attacks, but can also be checked on the database for so as long as endpoint `/user/signout` is not used.

## Usage with Thunder Client

The Library API can be tested locally via **Thunder Client**, a popular VS Code plugin. You can follow these steps to try it on your own:

1. Open **Thunder Client** in VS Code.
2. Create a new request for the desired endpoint:
-  **Method**: POST, GET, PUT, or DELETE.
-  **URL**: `http://127.0.0.1/library/public/<endpoint>`
-  **Authorization**: `Bearer < generated token>`
-  **Body**: For functions `POST`, `PUT`, &  `DELETE`, user will have provide the required JSON payload in the body.
3. For troubleshooting the API, the stated statuses for each fail response are stated in the documentation for ease of navigation on the code. These statuses do not reflect in the Status section of Thunder Client as it can return a code `200 OK` but the endpoint itself will return with a `fail` status.
  

## Endpoints
 This section covers the URL, description, method, body, and the sample responses of the API when it succeeds or fails.

### Books
#### /books/delete
-  **URL**: `http://127.0.0.1/library/public/books/delete`
-  **DESCRIPTION**: Deletes a book by its `bookid`
-  **Method**: DELETE
- **Authorization**: Bearer (generated token)
-  **Body**:
	```json
	{
		"bookid": 1
	}
	```
- **Response**:
	- **Success**:
		```
		{
		  "status": "success",
		  "data": null
		  "token": (generated token will appear here)
		}
		 ``` 
	 - **Fail (Status: 403)**:
		```
		{
		  "status": "fail",
		  "message": "Invalid or used token"
		}
		 ```
	 - **Fail (Status: 400)**:
		```
		{
		  "status": "fail",
		  "message": "Book ID is required"
		}
		 ```
		 
	 
#### /books/list
-  **URL**: `http://127.0.0.1/library/public/books/list`
-  **DESCRIPTION**: Lists all the title of the books and its `bookid` in the library database.
-  **Method**: GET
-  **Response**:
	- **Success**:
		```
		{
		  "status": "success",
		  "books": [
		    {
		      "bookid": 1,
		      "title": "The Seven Sundays"
		    }
		  ],
		  "token": "(generated token)"
		}
		 ``` 
	 - **Fail (Status: 403)**:
		```
		{
		  "status": "fail",
		  "message": "Invalid or used token"
		}
		 ```
	 - **Fail (Status: 401)**:
		```
		{
		  "status": "fail",
		  "message": "Unauthorized: Token missing user information."
		}
		 ```
#### /books/update
-  **URL**: `http://127.0.0.1/library/public/books/update`
-  **DESCRIPTION**: Update book details by ID
-  **Method**: PUT
    **Body**:
	```
	{
        "bookid": 1,
        "title": "sample title"
    }
	```

-  **Response**:
	- **Success**:
		```
		{
		  "status": "success",
		  "message": "Book updated sucessfully"
		}
		 ```
		 **Fail (Status: 403)**:
		  ```
		  {
			 "status": "fail",
             "message": "Unauthorized"
		  }
		  ```
		  **Fail (Status: 500)**:
		  {
			"status": "fail",
            "message": "Internal Server Error"
		  }
		  ```


#### /books/add
-  **URL**: `http://127.0.0.1/library/public/books/add`
-  **DESCRIPTION**: Add a new book
-  **Method**: POST
    **Body**:
	{
        "title": "sample title"
    }
	```

-  **Response**:
	- **Success**:
		```
		{
		  "status": "success",
		  "message": "Book added sucessfully"
		}
		 ```
		 **Fail (Status: 403)**:
		  ```
		  {
			 "status": "fail",
             "message": "Unauthorized"
		  }
		  ```
		  **Fail (Status: 500)**:
		  {
			"status": "fail",
            "message": "Internal Server Error"
		  }
		  ```



### Authors
#### /authors/add
-  **URL**: `http://127.0.0.1/library/public/authors/add`
-  **DESCRIPTION**: Adds a new author in the library database.
-  **Method**: POST
-  **Response**:
	```json
	{
		"name": "Jane Myers"
	}
	```
	- **Success**:
		```
		{
		  "status": "success",
		  "message": "Author added successfully",
		  "token": "(generated token)"
		}
		 ``` 
	 - **Fail (Status: 403)**:
		```
		{
		  "status": "fail",
		  "message": "Invalid or used token"
		}
		 ```
	 - **Fail (Status: 401)**:
		```
		{
		  "status": "fail",
		  "message": "Unauthorized: Token missing user information."
		}
		 ```
		 
#### /authors/update
-  **URL**: `http://127.0.0.1/library/public/authors/update`
-  **DESCRIPTION**: Updates an existing author in the library database.
-  **Method**: POST
-  **Response**:
	```json
	{
		"authorid": 1,
		"name": "Jane Doe"
	}
	```
	- **Success**:
		```
		{
		  "status": "success",
		  "message": "Author added successfully",
		  "token": "(generated token)"
		}
		 ``` 
	 - **Fail (Status: 400)**:
		```
		{
		  "status": "fail",
		  "message": "Author ID and name are required"
		}
		 ```
	 - **Fail (Status: 401)**:
		```
		{
		  "status": "fail",
		  "message": "Unauthorized: Token missing user information."
		}
		 ```
	 - **Fail (Status: 403)**:
		```
		{
		  "status": "fail",
		  "message": "Invalid or used token"
		}
		 ```
       
#### /authors/list
-  **URL**: `http://127.0.0.1/library/public/authors/list`
-  **DESCRIPTION**: Retrieve a list of authors
-  **Method**: GET
-  **Response**:
	```
	  **Fail (Status: 403)**:
		```
		{
		  "status": "fail",
          "message": "Unauthorized"
		}
		 ```
	 - **Fail (Status: 500)**:
		```
		{
		  "status": "fail",
		  "message": "Internal Server Error"
		}
		 ```


#### /authors/delete
-  **URL**: `http://127.0.0.1/library/public/authors/delete`
-  **DESCRIPTION**: Delete an author by ID
-  **Method**: DELETE
-   **Body**:
    {
		"authorid": 2
	}
	```
-  **Response**:  
    - **Success**:
	```
	{
		"status": "success",
        "message": "Author Deleted Successfully"
	}
	```
	  **Fail (Status: 403)**:
		```
		{
		  "status": "fail",
          "message": "Unauthorized"
		}
		 ```
	 - **Fail (Status: 500)**:
		```
		{
		  "status": "fail",
		  "message": "Internal Server Error"
		}
		 ```



### Users
#### /user/register
-  **URL**: `http://127.0.0.1/library/public/user/register`
-  **DESCRIPTION**: Registers a user, this endpoint also requires a unique username and password combination. Else, it will return a fail message. This endpoint does not utilize the HTTP Header `Authorization`.
-  **Method**: POST
-  **Response**:
	```json
	{
		"name": "Jane Doe",
		"password": "qwertyuiop"
	}
	```
	- **Success**:
		```
		{
		  "status": "success",
		  "data": null
		}
		 ``` 
	 - **Fail (Status: 400)**:
		```
		{
		  "status": "fail",
		  "message": "Username already exists"
		}
		 ```

#### /user/authenticate
-  **URL**: `http://127.0.0.1/library/public/user/authenticate`
-  **DESCRIPTION**: Authenticates a registered user and requires the token generated from the endpoint `/user/register` in order to return a session token that can be used once. This endpoint does not utilize the HTTP Header `Authorization`.
-  **Method**: POST
-  **Response**:
	```json
	{
		"name": "Jane Doe",
		"password": "qwertyuiop"
	}
	```
	- **Success**:
		```
		{
	 	  "status": "success",
		  "token": "(generated token)",
		  "data": null
		}
		 ``` 
	 - **Fail**:
		```
		{
		  "status": "fail",
		  "message": "Invalid username or password."
		}
		 ```

#### /user/login
-  **URL**: `http://127.0.0.1/library/public/user/login`
-  **DESCRIPTION**: Endpoint for registered and authenticated user, this endpoint also requires the token generated from `/user/authenticate`.
-  **Method**: POST
-  **Response**:
	```json
	{
		"name": "Jane Doe",
		"password": "qwertyuiop"
	}
	```
	- **Success**:
		```
		{
		  "status": "success",
		  "message": "Login successful",
	  	  "userid" : 1,
	  	  "username": "Jane Doe",
		  "token": "(generated token)"
		}
		 ``` 
	 - **Fail (Status: 401)**:
		```
		{
		  "status": "fail",
		  "message": "Invalid username or password."
		}
		 ```
#### /user/edit
-  **URL**: `http://127.0.0.1/library/public/user/edit`
-  **DESCRIPTION**: Edits a registered user in the library database. Does not require any tokens.
-  **Method**: POST
-  **Response**:
	```json
	{
		"userid": 1,
		"username": "Jane Doe"
	}
	```
	- **Success**:
		```
		{
		  "status": "success",
		  "data": null
		}
		 ``` 
	 - **Fail (Status: 400)**:
		```
		{
		  "status": "fail",
		  "message": "User ID and Username are required."
		}
		 ```
#### /user/delete
-  **URL**: `http://127.0.0.1/library/public/user/delete`
-  **DESCRIPTION**: User signout API, deletes all session tokens whether or not it was used .
-  **Method**: POST
-  **Response**:
	```json
	{
		"userid": 1
	}
	```
	- **Success**:
		```
		{
		  "status": "success",
		  "data": null
		}
		 ``` 
	 - **Fail (Status: 404)**:
		```
		{
		  "status": "fail",
		  "message": "userid not found"
		}
		 ```

#### /user/signout
-  **URL**: `http://127.0.0.1/library/public/user/signout`
-  **DESCRIPTION**: User signout endpoint, deletes all session tokens whether or not it was used by the user.
-  **Method**: POST
-  **Response**:
	```json
	{
		"name": "Jane Doe",
		"password": "qwertyuiop"
	}
	```
	- **Success**:
		```
		{
		  "status": "success",
		  "message": "Signed out successfully, all tokens deleted."
		}
		 ``` 
	 - **Fail (Status: 401)**:
		```
		{
		  "status": "fail",
		  "message": "Invalid username or password."
		}
		 ```

#### /collection/add
-  **URL**: `http://127.0.0.1/library/public/collection/add`
-  **DESCRIPTION**: Associate a book with an author
-  **Method**: POST
   **Body**:
   {
	"authorid": 1,
	"bookid": 3
   }
   ```
-  **Response**:
	- **Success**:
	```
	{
     "status": "success",
     "message": "Book-Author association added successfully"
	}
	```
	 - **Fail (Status: 403)**:
		```
		{
		 "status": "fail",
         "message": "Unauthorized"
		}
		 ```
	 - **Fail (Status: 404)**:
		```
		{
		 "status": "fail",
         "message": "Book or author not found"
		}
		 ```
	 - **Fail (Status: 500)**:
		```
		{
		 "status": "fail",
         "message": "Internal Server Error"
		}
		 ```


#### /collection/delete
-  **URL**: `http://127.0.0.1/library/public/collection/delete`
-  **DESCRIPTION**: Remove a book-author association
-  **Method**: DELETE
   **Body**:
   {
	"collectionid": 1
   }
   ```
-  **Response**:
	- **Success**:
	```
	{
    "status": "success",
    "message": "Book-Author association deleted successfully"
	}
	```
	 - **Fail (Status: 400)**:
		```
		{
		"status": "fail",
        "message": "Both book ID and author ID are required"
		}
		 ```
	 - **Fail (Status: 403)**:
		```
		{
		 "status": "fail",
         "message": "Unauthorized"
		}
		 ```
	 - **Fail (Status: 404)**:
		```
		{
		 "status": "fail",
         "message": "Association not found"
		}
		 ```
	- **Fail (Status: 500)**:
		```
		{
		 "status": "fail",
         "message": "Internal Server Error"
		}
		 ```

#### /collection/update
-  **URL**: `http://127.0.0.1/library/public/collection/update`
-  **DESCRIPTION**: Update a book-author association
-  **Method**: POST
   **Body**:
   {
	"authorid": 1,
	"bookid": 3
   }
   ```
-  **Response**:
	- **Success**:
	```
	{
    "status": "success",
    "message": "Book-Author association updated successfully"
	}
	```
	 - **Fail (Status: 400)**:
		```
		{
		"status": "fail",
        "message": "Both book ID and author ID are required"
		}
		 ```
	 - **Fail (Status: 403)**:
		```
		{
		 "status": "fail",
         "message": "Unauthorized"
		}
		 ```
	 - **Fail (Status: 404)**:
		```
		{
		 "status": "fail",
         "message": "Association not found"
		}
		 ```
	- **Fail (Status: 500)**:
		```
		{
		 "status": "fail",
         "message": "Internal Server Error"
		}
		 ```

#### /collection/list
-  **URL**: `http://127.0.0.1/library/public/collection/list`
-  **DESCRIPTION**: Retrieve a list of book-author associations
-  **Method**: GET
-  **Response**:
	 - **Fail (Status: 400)**:
		```
		{
		"status": "fail",
        "message": "Both book ID and author ID are required"
		}
		 ```


 ### UI CONTENTS
---

-The User Interface (UI) section covers the main features that allow users and administrators to interact with the platform. These components are designed to be intuitive and user-friendly, ensuring a smooth experience for everyone involved:

💻 REGISTER 
- Allow users to create a new account.

💻LOG IN
- Enable users to access their personal dashboard.

💻 DASHBOARD
- User's personalized interface to interact with the system.

💻 ADMIN LOG IN
- Dedicated login portal for administrators.

💻 ADMIN DASHBOARD     
- A management interface with elevated privileges for system administration.

🌐**FRONT-END API INTEGRATION**
---

- Our site uses HTTPOnly cookies to enhance security. These cookies are not accessible via JavaScript, which reduces the risk of attacks like XSS (Cross-Site Scripting). Instead, we use cross-authentication mechanisms to handle secure communication between the front end and back end. This ensures sensitive data is protected while maintaining seamless integration for the user.


👩‍💻**CONTRIBUTORS**
---

*QA TESTER & DOCUMENTATION: Eunice Fatima A. Delos Santos*

*DEVELOPER: Jashmin Joy C. Terrado*


