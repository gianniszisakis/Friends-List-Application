const express = require("express");

const router = express.Router();

let friends = {
  "johnsmith@gamil.com": {
    firstName: "John",
    lastName: "Doe",
    DOB: "22-12-1990",
  },
  "annasmith@gamil.com": {
    firstName: "Anna",
    lastName: "smith",
    DOB: "02-07-1983",
  },
  "peterjones@gamil.com": {
    firstName: "Peter",
    lastName: "Jones",
    DOB: "21-03-1989",
  },
};

//GET request: Retrieve all friends
router.get("/", (req, res) => {
  res.send(JSON.stringify(friends, null, 4));
});

//GET by specific ID request: Retrieve a single friend with email ID
router.get("/:email", (req, res) => {
  const email = req.params.email;
  res.send(friends[email]);
});

//POST request: add a new friend
router.post("/", (req, res) => {
  //check if email is provided in request body
  if (req.body.email) {
    //create or update friend details based on provided email
    friends[req.body.email] = {
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      DOB: req.body.DOB,
    };
  }
  res.send(`The user ${req.body.firstName} has been added`);
});

// PUT request: Update the details of a friend with email id
router.put("/:email", (req, res) => {
  //extract email param from requested URL
  const email = req.params.email;
  let friend = friends[email]; //retrieve the friend with the email of the req

  if (friend) {
    let DOB = req.body.DOB;
    let firstName = req.body.firstName;
    let lastName = req.body.lastName;

    if (DOB) {
      friend["DOB"] = DOB;
    }

    if (firstName) {
      friend["firstName"] = firstName;
    }

    if (lastName) {
      friend["lastName"] = lastName;
    }

    friends["email"] = friend; //update friend details in friends object
    res.send(`The friend ${email} updated`);
  } else {
    res.send("Unable to find friend");
  }
});

// DELETE request: Delete a friend by email id
router.delete("/:email", (req, res) => {
  const email = req.params.email;

  if (email) {
    delete friends[email];
  }

  res.send(`Friend with email ${email} has been deleted`);
});
