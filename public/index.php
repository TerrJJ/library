<?php

use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
  require '../src/vendor/autoload.php';
  $app = new \Slim\App;

  $app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $usr = $data->username;
    $pass = $data->password;

    $servername = "localhost";
    $username = "root";
    $password = "passroot1";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if username already exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->execute(['username' => $usr]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            return $response->withStatus(400)->getBody()->write(json_encode([
                "status" => "fail",
                "message" => "Username already exists"
            ]));
        }

        // Insert new user if username is unique
        $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['username' => $usr, 'password' => hash('SHA256', $pass)]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => null]));

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }

    return $response;
  });

  $app->post('/user/authenticate', function (Request $request, Response $response) {
      $data = json_decode($request->getBody());
      $username = $data->username;
      $password = $data->password;

      $key = 'server_hack';
      $servername = "localhost";
      $db_username = "root";
      $db_password = "passroot1";
      $dbname = "library";

      try {
          $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $db_password);
          $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

          $hashedPassword = hash('SHA256', $password);

          $sql = "SELECT * FROM users WHERE username = :username AND password = :password";
          $stmt = $conn->prepare($sql);
          $stmt->bindParam(':username', $username);
          $stmt->bindParam(':password', $hashedPassword);
          $stmt->execute();
          $user = $stmt->fetch(PDO::FETCH_ASSOC);

          if ($user) {
              $iat = time();
              $exp = $iat+60;

              $payload = [
                  'iss' => 'http://library.org',
                  'aud' => 'http://library.com',  
                  'iat' => $iat,  
                  'exp' => $exp,
                  'data' => [
                      'userid' => $user['userid'],
                      'username' => $user['username']
                  ]
              ];

              $jwt = JWT::encode($payload, $key, 'HS256');

              $response->getBody()->write(json_encode([
                  "status" => "success",
                  "token" => $jwt,
                  "data" => null
              ]));
          } else {
              $response->getBody()->write(json_encode([
                  "status" => "fail",
                  "message" => "Invalid username or password."
              ]));
          }
      } catch (PDOException $e) {
          return $response->withStatus(500)->getBody()->write(json_encode([
              "status" => "fail",
              "message" => $e->getMessage()
          ]));
      }

      return $response->withHeader('Content-Type', 'application/json');
  });

  $app->get('/user/list', function (Request $request, Response $response) {
    try {
        $conn = new PDO("mysql:host=localhost;dbname=library", 'root', 'passroot1');
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users";
        $stmt = $conn->query($sql);
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $users = $stmt->fetchAll();

        $response->getBody()->write(json_encode(array("status" => "success", "data" => $users)));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
  });

  $app->put('/user/edit', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (!isset($data->userid) || !isset($data->username)) {
        return $response->withStatus(400)->getBody()->write(json_encode(array("status" => "fail", "message" => "User ID and Username are required.")));
    }

    $userid = $data->userid;
    $usrname = $data->username;

    try {
        $conn = new PDO("mysql:host=localhost;dbname=library", 'root', 'passroot1');
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE users SET username = :username WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':username', $usrname);
        $stmt->bindParam(':userid', $userid);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
  });

  $app->delete('/user/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());
    $userid = $data->userid;

    try {
        $conn = new PDO("mysql:host=localhost;dbname=library", 'root', 'passroot1');
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM users WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':userid', $userid);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
  });

  $app->post('/user/login', function (Request $request, Response $response) {
    $key = 'server_hack';
    $servername = "localhost";
    $db_username = "root";
    $db_password = "passroot1";
    $dbname = "library";

    $data = json_decode($request->getBody());
    $username = $data->username;
    $password = $data->password;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $db_password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Hash the password using the same method as user registration
        $hashedPassword = hash('SHA256', $password);

        // Check if the username and password are valid
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
        $stmt->execute(['username' => $username, 'password' => $hashedPassword]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $iat = time();
            $exp = $iat+60;
            $payload = [
                'iat' => $iat,
                'exp' => $exp,
                'data' => [
                    'userid' => $user['userid'],
                    'username' => $user['username']
                ]
            ];

            // Encode the token
            $sessionToken = JWT::encode($payload, $key, 'HS256');

            // Insert the token into the tokens table
            $stmt = $conn->prepare("INSERT INTO tokens (token, is_used) VALUES (:token, 0)");
            $stmt->execute(['token' => $sessionToken]);

            // Return the session token along with the user details
            $response->getBody()->write(json_encode([
                "status" => "success",
                "message" => "Login successful.",
                "userid" => $user['userid'],
                "username" => $user['username'],
                "token" => $sessionToken
            ]));
        } else {
            // Invalid credentials
            return $response->withStatus(401)->getBody()->write(json_encode([
                "status" => "fail",
                "message" => "Invalid username or password."
            ]));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode([
            "status" => "fail",
            "message" => $e->getMessage()
        ]));
    }

    return $response->withHeader('Content-Type', 'application/json');
  });

  //modified endpoints;
  $app->post('/authors/add', function (Request $request, Response $response) {
    $key = 'server_hack';
    $token = $request->getHeader('Authorization')[0];
    $token = str_replace('Bearer ', '', $token);

    $servername = "localhost";
    $db_username = "root";
    $db_password = "passroot1";
    $dbname = "library";

    $data = json_decode($request->getBody());
    $authorName = $data->name;

    if (!isset($authorName)) {
        return $response->withStatus(400)->getBody()->write(json_encode([
            'status' => 'fail',
            'message' => 'Author name is required'
        ]));
    }

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $db_password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Validate the token
        $stmt = $conn->prepare("SELECT * FROM tokens WHERE token = :token AND is_used = 0");
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$tokenRecord) {
            return $response->withStatus(403)->getBody()->write(json_encode([
                'status' => 'fail',
                'message' => 'Invalid or used token'
            ]));
        }

        // Decode the token
        try {
            $decodedToken = JWT::decode($token, new Key($key, 'HS256'));
            if (!isset($decodedToken->data->userid)) {
                return $response->withStatus(401)->getBody()->write(json_encode([
                    'status' => 'fail',
                    'message' => 'Unauthorized: Token missing user information.'
                ]));
            }
        } catch (Exception $e) {
            return $response->withStatus(403)->getBody()->write(json_encode([
                'status' => 'fail',
                'message' => 'Unauthorized: Invalid or expired token.'
            ]));
        }

        // Insert the new author
        $stmt = $conn->prepare("INSERT INTO authors (name) VALUES (:name)");
        $stmt->execute(['name' => $authorName]);

        // Mark the token as used
        $stmt = $conn->prepare("UPDATE tokens SET is_used = 1 WHERE token = :token");
        $stmt->execute(['token' => $token]);

        // Return a new token for the next request
        $iat = time();
        $exp = $iat+60;
        $payload = [
            'iat' => $iat,
            'exp' => $exp,
            'data' => [
                'userid' => $decodedToken->data->userid,
                'username' => $decodedToken->data->username
            ]
        ];
        $newToken = JWT::encode($payload, $key, 'HS256');
        $stmt = $conn->prepare("INSERT INTO tokens (token, is_used) VALUES (:token, 0)");
        $stmt->execute(['token' => $newToken]);

        return $response->getBody()->write(json_encode([
            'status' => 'success',
            'message' => 'Author added successfully',
            'token' => $newToken
        ]));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode([
            'status' => 'fail',
            'message' => $e->getMessage()
        ]));
    }
  });

  $app->delete('/books/delete', function (Request $request, Response $response) {
    $key = 'server_hack';
    $token = $request->getHeader('Authorization')[0];
    $token = str_replace('Bearer ', '', $token);

    $servername = "localhost";
    $db_username = "root";
    $db_password = "passroot1";
    $dbname = "library";

    $data = json_decode($request->getBody());
    $bookid = $data->bookid;

    if (!isset($bookid)) {
        return $response->withStatus(400)->getBody()->write(json_encode([
            'status' => 'fail',
            'message' => 'Book ID is required'
        ]));
    }

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $db_password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Validate the token
        $stmt = $conn->prepare("SELECT * FROM tokens WHERE token = :token AND is_used = 0");
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$tokenRecord) {
            return $response->withStatus(403)->getBody()->write(json_encode([
                'status' => 'fail',
                'message' => 'Invalid or used token'
            ]));
        }

        // Decode the token
        try {
            $decodedToken = JWT::decode($token, new Key($key, 'HS256'));
            if (!isset($decodedToken->data->userid)) {
                return $response->withStatus(401)->getBody()->write(json_encode([
                    'status' => 'fail',
                    'message' => 'Unauthorized: Token missing user information.'
                ]));
            }
        } catch (Exception $e) {
            return $response->withStatus(403)->getBody()->write(json_encode([
                'status' => 'fail',
                'message' => 'Unauthorized: Invalid or expired token.'
            ]));
        }

        // Delete the book
        $stmt = $conn->prepare("DELETE FROM books WHERE bookid = :bookid");
        $stmt->execute(['bookid' => $bookid]);

        // Mark the token as used
        $stmt = $conn->prepare("UPDATE tokens SET is_used = 1 WHERE token = :token");
        $stmt->execute(['token' => $token]);

        // Return a new token for the next request
        $iat = time();
        $exp = $iat+60;
        $payload = [
            'iat' => $iat,
            'exp' => $exp,
            'data' => [
                'userid' => $decodedToken->data->userid,
                'username' => $decodedToken->data->username
            ]
        ];
        $newToken = JWT::encode($payload, $key, 'HS256');
        $stmt = $conn->prepare("INSERT INTO tokens (token, is_used) VALUES (:token, 0)");
        $stmt->execute(['token' => $newToken]);

        return $response->getBody()->write(json_encode([
            'status' => 'success',
            'message' => 'Book deleted successfully',
            'token' => $newToken
        ]));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode([
            'status' => 'fail',
            'message' => $e->getMessage()
        ]));
    }
  });

  $app->get('/books/list', function (Request $request, Response $response) {
    $key = 'server_hack';
    $token = $request->getHeader('Authorization')[0];
    $token = str_replace('Bearer ', '', $token);

    $servername = "localhost";
    $db_username = "root";
    $db_password = "passroot1";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $db_password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Validate the token
        $stmt = $conn->prepare("SELECT * FROM tokens WHERE token = :token AND is_used = 0");
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$tokenRecord) {
            return $response->withStatus(403)->getBody()->write(json_encode([
                'status' => 'fail',
                'message' => 'Invalid or used token'
            ]));
        }

        // Decode the token
        try {
            $decodedToken = JWT::decode($token, new Key($key, 'HS256'));
            if (!isset($decodedToken->data->userid)) {
                return $response->withStatus(401)->getBody()->write(json_encode([
                    'status' => 'fail',
                    'message' => 'Unauthorized: Token missing user information.'
                ]));
            }
        } catch (Exception $e) {
            return $response->withStatus(403)->getBody()->write(json_encode([
                'status' => 'fail',
                'message' => 'Unauthorized: Invalid or expired token.'
            ]));
        }

        // Retrieve the list of books
        $stmt = $conn->prepare("SELECT bookid, title FROM books");
        $stmt->execute();
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Mark the token as used
        $stmt = $conn->prepare("UPDATE tokens SET is_used = 1 WHERE token = :token");
        $stmt->execute(['token' => $token]);

        // Return a new token for the next request
        $iat = time();
        $exp = $iat+60;
        $payload = [
            'iat' => $iat,
            'exp' => $exp,
            'data' => [
                'userid' => $decodedToken->data->userid,
                'username' => $decodedToken->data->username
            ]
        ];
        $newToken = JWT::encode($payload, $key, 'HS256');
        $stmt = $conn->prepare("INSERT INTO tokens (token, is_used) VALUES (:token, 0)");
        $stmt->execute(['token' => $newToken]);

        return $response->getBody()->write(json_encode([
            'status' => 'success',
            'books' => $books,
            'token' => $newToken
        ]));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode([
            'status' => 'fail',
            'message' => $e->getMessage()
        ]));
    }
  });

  $app->post('/authors/update', function (Request $request, Response $response) {
    $key = 'server_hack';
    $token = $request->getHeader('Authorization')[0];
    $token = str_replace('Bearer ', '', $token);

    $servername = "localhost";
    $db_username = "root";
    $db_password = "passroot1";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $db_password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Validate the token
        $stmt = $conn->prepare("SELECT * FROM tokens WHERE token = :token AND is_used = 0");
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$tokenRecord) {
            return $response->withStatus(403)->getBody()->write(json_encode([
                'status' => 'fail',
                'message' => 'Invalid or used token'
            ]));
        }

        // Decode the token
        try {
            $decodedToken = JWT::decode($token, new Key($key, 'HS256'));
            if (!isset($decodedToken->data->userid)) {
                return $response->withStatus(401)->getBody()->write(json_encode([
                    'status' => 'fail',
                    'message' => 'Unauthorized: Token missing user information.'
                ]));
            }
        } catch (Exception $e) {
            return $response->withStatus(403)->getBody()->write(json_encode([
                'status' => 'fail',
                'message' => 'Unauthorized: Invalid or expired token.'
            ]));
        }

        // Get the data from the request body
        $data = json_decode($request->getBody());
        $authorid = $data->authorid;
        $name = $data->name;

        if (!isset($authorid) || !isset($name)) {
            return $response->withStatus(400)->getBody()->write(json_encode([
                'status' => 'fail',
                'message' => 'Author ID and name are required'
            ]));
        }

        // Update the author's name in the database
        $stmt = $conn->prepare("UPDATE authors SET name = :name WHERE authorid = :authorid");
        $stmt->execute(['name' => $name, 'authorid' => $authorid]);

        // Mark the token as used
        $stmt = $conn->prepare("UPDATE tokens SET is_used = 1 WHERE token = :token");
        $stmt->execute(['token' => $token]);

        // Return a new token for the next request
        $iat = time();
        $exp = $iat+60;
        $payload = [
            'iat' => $iat,
            'exp' => $exp,
            'data' => [
                'userid' => $decodedToken->data->userid,
                'username' => $decodedToken->data->username
            ]
        ];
        $newToken = JWT::encode($payload, $key, 'HS256');
        $stmt = $conn->prepare("INSERT INTO tokens (token, is_used) VALUES (:token, 0)");
        $stmt->execute(['token' => $newToken]);

        return $response->getBody()->write(json_encode([
            'status' => 'success',
            'message' => 'Author updated successfully.',
            'token' => $newToken
        ]));
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode([
            'status' => 'fail',
            'message' => $e->getMessage()
        ]));
    }
  });

  $app->post('/user/signout', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());
    $username = $data->username;
    $password = $data->password;

    $servername = "localhost";
    $db_username = "root";
    $db_password = "passroot1";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $db_password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Hash the provided password to match with the stored one
        $hashedPassword = hash('SHA256', $password);

        // Check if the username and password are correct
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
        $stmt->execute(['username' => $username, 'password' => $hashedPassword]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Delete all tokens from the tokens table since the user is signing out
            $stmt = $conn->prepare("DELETE FROM tokens");
            $stmt->execute();

            return $response->getBody()->write(json_encode([
                'status' => 'success',
                'message' => 'Signed out successfully, all tokens deleted.'
            ]));
        } else {
            return $response->withStatus(401)->getBody()->write(json_encode([
                'status' => 'fail',
                'message' => 'Invalid username or password.'
            ]));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->getBody()->write(json_encode([
            'status' => 'fail',
            'message' => $e->getMessage()
        ]));
    }
  });

$app->run();

?>