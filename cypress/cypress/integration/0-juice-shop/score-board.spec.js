/// <reference types="cypress" />

describe('Test de seguridad de Juice Shop', () => {
  beforeEach(() => {
    cy.clearCookies();
    cy.clearLocalStorage();

    cy.on('uncaught:exception', () => false)
    cy.visit('http://localhost:3000/#/')
    cy.get('.close-dialog > .mat-button-wrapper > .mat-icon').click()
  })

  it('Accedemos al Score Board', () => {
    cy.visit('/#/score-board')
    cy.get('.mat-card-title').invoke('text').should('contain', 'Score Board')
    cy.get('[id^="Score\ Board\.solved"]').scrollIntoView().should('have.length', 1)
  })
})
