"""Self-improving defence loop: red team, blue team, defence memory and the validation gate.

This is a defensive security component. The red team runs only against Warden's own lab
agents and mock services to find gaps so the blue team can close them; it never targets any
third-party system. Attack seeds come from the project's committed corpus, not from this code.
"""
